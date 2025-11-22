Project: connwatch

1. High level description

Build a terminal-based, fullscreen TUI application in Rust that:
	•	Monitors all network connections from/to the local machine in near real time.
	•	Shows them in a 3-column layout:
	•	Left: spinning ASCII globe with markers for remote IPs.
	•	Middle: live list of current connections.
	•	Right: detailed information about the selected connection, enriched with lookups and optional Nmap scans.
	•	Stores all connection events and metadata in a local database file so the data can be queried later, grouped by IP, time, etc.
	•	Has CLI flags to enable or disable each column independently.

The entire interface runs in the terminal, using ratatui (or similar) and a crossterm backend. No GUI windows.

⸻

2. Tech stack and dependencies

Create a Rust binary crate called connwatch.

Suggested crates:
	•	TUI:
	•	ratatui (or tui if you prefer, but use ratatui by default)
	•	crossterm as the backend for input/output
	•	CLI parsing:
	•	clap with derive macros
	•	Packet capture / connection tracking:
	•	pcap or tokio-pcap (sync is fine to start, async optional)
	•	IP / protocol parsing:
	•	pnet_packet or custom parsers for TCP/UDP/IPv4/IPv6
	•	DNS / reverse lookup:
	•	trust-dns-resolver or call getaddrinfo via std::net and dns-lookup
	•	Geolocation (for globe markers):
	•	maxminddb (use an mmdb file specified by user via CLI or config)
	•	Database:
	•	rusqlite (simple SQLite file) or sqlx with sqlite feature
	•	Time:
	•	chrono or time
	•	Serialisation:
	•	serde, serde_json (for config, debugging or export)
	•	Async runtime (optional but recommended):
	•	tokio
	•	Subprocess / Nmap:
	•	tokio::process or std::process::Command
	•	Globe:
	•	Add the globe crate as a git dependency:

[dependencies]
globe = { git = "https://github.com/adamsky/globe" }

If it does not expose a library interface, vendor the relevant code into a globe module and adapt as needed.

⸻

3. Command line interface

Use clap to define the following:

Binary name: connwatch

Supported flags:
	•	--interface, -i <IFACE>
Network interface to capture on. If omitted, choose a sensible default (first non-loopback interface).
	•	--db-path <PATH>
Path to SQLite database file. Default: ~/.local/share/connwatch/connwatch.db (on Unix). Create directories if they do not exist.
	•	--no-globe
Disable left column globe.
	•	--no-list
Disable middle column connection list.
	•	--no-detail
Disable right column detail panel.
	•	--enable-nmap
Enable external Nmap scans for new remote IPs.
	•	--nmap-ports "22,80,443,8080"
Comma separated list of ports for the Nmap scan.
	•	--mmdb-path <PATH>
Path to MaxMind GeoIP2 / GeoLite2 mmdb file.
	•	--pcap-filter <BPF> (optional)
Custom BPF filter for pcap (for example excluding local subnets).
	•	--log-level <LEVEL>
Logging level (info, debug, trace).

Configuration precedence:
	1.	CLI flags
	2.	Environment variables (optional)
	3.	Config file (optional)

For this initial version, CLI arguments are enough.

⸻

4. Application architecture

Split the crate into modules:
	•	main.rs
	•	Parses CLI arguments.
	•	Initialises logging.
	•	Opens database.
	•	Sets up shared application state.
	•	Spawns:
	•	packet capture / connection tracking task
	•	Nmap scanning worker (if enabled)
	•	TUI event loop
	•	config.rs
	•	Defines a Config struct with all settings.
	•	Populates it from clap arguments.
	•	capture/mod.rs
	•	Handles pcap initialisation and packet reading.
	•	Normalises packets to a generic ConnectionKey:

struct ConnectionKey {
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    protocol: TransportProtocol, // TCP/UDP/Other
}


	•	Emits high-level events like ConnectionOpened, ConnectionUpdated, ConnectionClosed, and RequestObserved.

	•	model.rs
	•	Defines core data structures:
	•	Connection
	•	ConnectionEvent
	•	HttpRequest (for parsed HTTP)
	•	EndpointInfo
	•	ScanStatus and ScanResult
	•	Also holds enums like TransportProtocol, ApplicationProtocol.
	•	storage.rs
	•	Wraps SQLite access.
	•	Functions to:
	•	Create tables if missing.
	•	Insert/update connections.
	•	Insert HTTP request metadata.
	•	Insert Nmap scan results.
	•	Query history for a given IP or time frame.
	•	analysis.rs
	•	Logic to detect application protocols (simple heuristics).
	•	For HTTP on port 80 or 8080:
	•	Parse HTTP request line and headers.
	•	Extract method, path, Host header, and possibly Authorization header.
	•	Store this in the database.
	•	Important: do not try to decrypt HTTPS, just record SNI if possible and port 443.
	•	For SSH:
	•	You can capture server banner from first plaintext packet (for example SSH-2.0-OpenSSH_9.0).
	•	Store banner, but do not attempt to pull credentials from encrypted streams.
	•	globe_view.rs
	•	Integration with globe crate.
	•	Takes a list of remote endpoints with lat/long and draws them into a ratatui widget.
	•	tui/mod.rs
	•	TUI framework:
	•	Draw layout according to enabled columns.
	•	Handle user input (navigation, quitting, toggling view, filters).
	•	Display globe, connection list, and detail panel.
	•	Submodules:
	•	layout.rs
	•	widgets/connection_list.rs
	•	widgets/detail_panel.rs
	•	widgets/globe_widget.rs
	•	nmap.rs
	•	If --enable-nmap is set:
	•	Queue new unseen remote IPs for scanning.
	•	Use Command::new("nmap") with -sC -sV -p <ports> and -oX - (XML to stdout) or -oN - and parse text.
	•	Store scan results in the database.
	•	Maintain a rate limit to avoid hammering networks.

⸻

5. Data model and database schema

Use SQLite.

Create tables that roughly look like:

CREATE TABLE IF NOT EXISTS connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen      INTEGER NOT NULL,  -- unix timestamp
    last_seen       INTEGER NOT NULL,
    src_ip          TEXT NOT NULL,
    src_port        INTEGER NOT NULL,
    dst_ip          TEXT NOT NULL,
    dst_port        INTEGER NOT NULL,
    transport       TEXT NOT NULL,     -- "TCP" or "UDP"
    app_protocol    TEXT,              -- "HTTP", "HTTPS", "SSH", ...
    state           TEXT,              -- "OPEN", "CLOSED", "ESTABLISHED", etc.
    bytes_sent      INTEGER NOT NULL DEFAULT 0,
    bytes_recv      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_connections_dst_ip ON connections(dst_ip);
CREATE INDEX IF NOT EXISTS idx_connections_time ON connections(first_seen, last_seen);

CREATE TABLE IF NOT EXISTS http_requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id   INTEGER NOT NULL REFERENCES connections(id),
    ts              INTEGER NOT NULL,
    method          TEXT,
    host            TEXT,
    path            TEXT,
    http_version    TEXT,
    authorization   TEXT,   -- optional, can be NULL or truncated/redacted if desired
    user_agent      TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    dst_ip          TEXT NOT NULL,
    ts              INTEGER NOT NULL,
    status          TEXT NOT NULL,     -- "PENDING", "RUNNING", "DONE", "FAILED"
    ports           TEXT,              -- original port list
    result_raw      TEXT               -- Nmap output (XML or text)
);

CREATE INDEX IF NOT EXISTS idx_scans_dst_ip ON scans(dst_ip);

CREATE TABLE IF NOT EXISTS endpoint_info (
    ip              TEXT PRIMARY KEY,
    country         TEXT,
    city            TEXT,
    latitude        REAL,
    longitude       REAL,
    hostname        TEXT,
    last_updated    INTEGER
);

The detail panel should read from these tables to show:
	•	Basic connection tuple.
	•	Resolved hostname.
	•	Geolocation (country, city, coordinates).
	•	Latest HTTP requests for that connection (method, host, path, User-Agent, auth header if present).
	•	Nmap scan summary if available.

⸻

6. Packet capture and connection tracking

6.1 Packet capture

Use pcap to:
	•	Open the selected interface in promiscuous mode, if allowed.
	•	Apply a reasonable default filter, for example:
	•	tcp or udp as base.
	•	If the user provides --pcap-filter, apply that instead.

Loop over captured packets and:
	1.	Parse link layer header.
	2.	Extract IPv4/IPv6 header.
	3.	Extract TCP/UDP header.
	4.	Build ConnectionKey.
	5.	Derive direction:
	•	Determine which side is “local” (matches one of the host’s IP addresses).
	•	Mark local vs remote in the Connection struct.

Maintain an Arc<Mutex<HashMap<ConnectionKey, ConnectionState>>> or similar shared structure:

struct ConnectionState {
    connection: Connection,      // basic info, timestamps, counters
    last_packet_ts: SystemTime,
}

Every packet:
	•	If key not present:
	•	Create new Connection.
	•	Set first_seen and last_seen.
	•	Store in map.
	•	Upsert into DB (insert row if new).
	•	If key present:
	•	Update last_seen, bytes sent/received.
	•	On direction, increase sent/received accordingly.
	•	Update DB row.

Periodically:
	•	Evict connections that have been idle for longer than a timeout (for example 60 seconds for TCP, 30 seconds for UDP).
	•	Mark state = "CLOSED" in DB if they expire.

Use a channel to send events into the TUI thread so that the UI can update live without polling the DB constantly.

6.2 Application protocol detection

In analysis.rs:
	•	If dst_port or src_port is in {80, 8080}, treat packets as HTTP candidates.
	•	Look for the start of HTTP request lines: METHOD SP PATH SP HTTP/1.x.
	•	Parse headers until blank line.
	•	Extract Host, User-Agent, Authorization.
	•	Store in http_requests table.
	•	Set app_protocol = "HTTP" for that connection.
	•	If port is 443 and TLS ClientHello/SNI is visible:
	•	Extract Server Name Indication if possible, store as hostname.
	•	Set app_protocol = "HTTPS".
	•	If port is 22 and first bytes start with "SSH-":
	•	Capture that banner string, store as part of connection metadata.
	•	Set app_protocol = "SSH".

Avoid attempting to decode credentials from encrypted protocols. For HTTP, you can store the Authorization header as is, but this should be considered sensitive and possibly an opt-in.

⸻

7. Nmap integration

Only run Nmap if --enable-nmap is set and nmap is available on $PATH.

Design:
	•	Maintain a queue of IPs to scan (for example a tokio::mpsc::Sender<String>).
	•	When a new remote IP appears (first time seen, not in endpoint_info and scans), push it into the queue.
	•	In a separate async task, consume queue items and:
	1.	Insert a PENDING row into scans.
	2.	Run:

nmap -sC -sV -p <ports> -oX - <ip>


	3.	Capture stdout.
	4.	Mark scan as DONE and store raw XML in result_raw.
	5.	Optionally parse out a small summary (open ports, service names, versions) to show in the detail panel.

Rate limiting:
	•	Only one scan at a time.
	•	Optional small delay between scans (for example 5 seconds).

⸻

8. Geolocation and globe

To render the globe:
	1.	For each remote IP currently active:
	•	Check endpoint_info table for existing coordinates.
	•	If missing:
	•	Use maxminddb with the user provided --mmdb-path to look up geolocation.
	•	Insert into endpoint_info.
	2.	Convert lat/long to whatever coordinate system the globe crate needs for placing markers.
	3.	In globe_view.rs, combine the globe crate output with ratatui:
	•	Render the globe into an off-screen buffer.
	•	Convert that buffer into a ratatui::widgets::Paragraph or ratatui::widgets::Canvas.
	•	Draw markers (for example by changing characters or overlaying coloured symbols at specific positions).
	4.	Rotate the globe over time to give a spinning effect.
	5.	Do not block UI during geolocation lookup. Use background tasks and cache results.

If --no-globe is set, skip all of this and free the column width for other parts.

⸻

9. TUI design

Use ratatui with crossterm. The app should go fullscreen and restore the terminal on exit.

9.1 Layout

Base layout: 3 vertical columns.
	•	If all columns enabled:
	•	Left: 30% width globe.
	•	Middle: 35% width connections.
	•	Right: 35% width detail.
	•	If one column disabled:
	•	Redistribute space between remaining columns proportionally.
	•	If two columns disabled:
	•	Single column fullscreen.

Implement a Layout calculation that depends on config flags.

9.2 Widgets

Middle column: connection list
	•	Table or list with columns:
	•	Direction (in/out)
	•	Local addr:port
	•	Remote addr:port
	•	Protocol (TCP/UDP + app protocol if known)
	•	Bytes sent / received
	•	State
	•	Last seen relative time (for example “5 s ago”)
	•	Sort by last_seen descending.
	•	Allow navigation with arrow keys / j, k.
	•	Highlight selected connection.

Right column: detail panel
	•	Show:
	•	Connection tuple and state.
	•	Hostname and geolocation of remote IP.
	•	Recent HTTP requests (stacked).
	•	Nmap summary.
	•	If there are multiple HTTP requests, show last N items and allow scrolling.

Left column: globe
	•	Shows world map and markers for currently active remote IPs.
	•	Optionally show selected connection’s marker in a different style.

9.3 Input / keybindings

Basic controls:
	•	q or Ctrl-c: exit.
	•	Tab: cycle focus between columns (when enabled).
	•	Up / Down or j / k: scroll connection list or detail panel depending on focus.
	•	PgUp / PgDn: scroll faster.
	•	/: open a quick filter prompt for host/IP (optional).
	•	g / G: jump to top/bottom in list.

All input handling lives in a tui::event module, with an event loop that:
	1.	Polls for input events using crossterm::event::read.
	2.	Polls for app state updates from channels (connwatch messages).
	3.	Redraws at a fixed interval (for example 100 ms) or whenever needed.

⸻

10. Privacy, security and permissions
	•	Packet capture and Nmap usually require root or CAP_NET_RAW / CAP_NET_ADMIN.
	•	The tool is meant for local monitoring of your own machine. Do not provide any functionality to inject packets or attack other hosts.
	•	While HTTP headers can contain credentials (for example Basic Auth), treat that as sensitive:
	•	Either redact the secret parts or make storing full Authorization headers optional behind a flag, for example --log-auth-headers.
	•	For encrypted protocols (HTTPS, SSH), no credential logging is intended. Only metadata like IPs, ports, hostnames, banners, and certificate info if visible should be stored.

⸻

11. State management and concurrency

Use a shared AppState struct in tui:

pub struct AppState {
    pub connections: Vec<ConnectionView>,   // flattened for UI
    pub selected_index: usize,
    pub show_globe: bool,
    pub show_list: bool,
    pub show_detail: bool,
}

ConnectionView is a reduced representation of the full Connection plus some derived fields.

The capture task:
	•	Owns the authoritative HashMap<ConnectionKey, ConnectionState>.
	•	Writes updates into the DB.
	•	Sends simplified events to the TUI thread via an mpsc channel, for example:
	•	ConnectionAdded(ConnectionView)
	•	ConnectionUpdated(ConnectionView)
	•	ConnectionClosed(ConnectionKey)

The TUI thread:
	•	Applies these changes to its local AppState.
	•	Triggers re-draws.

Use tokio::spawn to run these tasks concurrently.

⸻

12. Testing and development notes
	•	Provide a --pcap-file <PATH> option in a dev build to read from an offline pcap file instead of live capture. This makes it easier to test without root.
	•	Add a mock module that can feed fake connection events into the TUI for snapshot testing.
	•	Implement integration tests for:
	•	Database schema creation.
	•	Round-tripping a Connection insert/update.
	•	Parsing sample HTTP request bytes.
	•	Parsing sample Nmap XML.

⸻
