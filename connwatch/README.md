# connwatch

Terminal-based, full-screen network connection monitor with a globe, live connection list, and detail pane.

## Features
- Live packet capture with pcap (interface selectable via CLI).
- Ratatui + crossterm TUI:
  - Left: ASCII globe with geo-markers.
  - Right top: connection list.
  - Right bottom: detail panel with host metadata and optional ipinfo for private IPs.
- SQLite storage for connections, HTTP metadata, scans, and endpoint info.
- Optional Nmap scans on new remote IPs.
- Optional MaxMind mmdb geolocation for globe markers.
- Offline testing via `--pcap-file`.

## Quick start
```bash
cargo run -- --interface <iface> --mmdb-path /path/to/GeoLite2-City.mmdb
# or offline:
cargo run -- --pcap-file sample.pcap
```

Useful flags:
- `--interface/-i <IFACE>`: capture interface (required for live capture).
- `--pcap-file <PATH>`: read packets from a pcap file instead of live capture.
- `--pcap-filter <BPF>`: custom BPF filter.
- `--db-path <PATH>`: SQLite file (default `~/.local/share/connwatch/connwatch.db`).
- `--no-globe`, `--no-list`, `--no-detail`: hide columns.
- `--enable-nmap --nmap-ports "22,80,443"`: run Nmap on new remote IPs.
- `--mmdb-path <PATH>`: MaxMind mmdb for geolocation.
- `--log-level <LEVEL>`: info/debug/trace.

## Notes
- Live capture may require root/CAP_NET_RAW. Use `--pcap-file` for unprivileged testing.
- ipinfo integration shows only for private/loopback remote IPs and requires the `ipinfo` binary on PATH.
- Nmap integration requires `nmap` on PATH and is opt-in via `--enable-nmap`.
