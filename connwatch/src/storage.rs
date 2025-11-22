use std::fs;
use std::path::Path;

use anyhow::Context;
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{params, Connection as SqlConnection};

use crate::model::{
    ApplicationProtocol, Connection, ConnectionKey, EndpointInfo, HttpRequest, ScanResult,
    ScanStatus, TransportProtocol,
};

pub struct Storage {
    conn: SqlConnection,
}

impl Storage {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create database directory {parent:?}"))?;
        }
        let conn = SqlConnection::open(path)
            .with_context(|| format!("failed to open database at {}", path.display()))?;
        Ok(Self { conn })
    }

    pub fn init_schema(&self) -> anyhow::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS connections (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                first_seen      INTEGER NOT NULL,
                last_seen       INTEGER NOT NULL,
                src_ip          TEXT NOT NULL,
                src_port        INTEGER NOT NULL,
                dst_ip          TEXT NOT NULL,
                dst_port        INTEGER NOT NULL,
                transport       TEXT NOT NULL,
                app_protocol    TEXT,
                state           TEXT,
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
                authorization   TEXT,
                user_agent      TEXT
            );

            CREATE TABLE IF NOT EXISTS scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                dst_ip          TEXT NOT NULL,
                ts              INTEGER NOT NULL,
                status          TEXT NOT NULL,
                ports           TEXT,
                result_raw      TEXT
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
            "#,
        )?;
        Ok(())
    }

    pub fn insert_or_update_connection(&self, conn: &mut crate::model::Connection) -> anyhow::Result<()> {
        if let Some(id) = conn.id {
            self.conn.execute(
                "UPDATE connections SET last_seen = ?, state = ?, bytes_sent = ?, bytes_recv = ?, app_protocol = ? WHERE id = ?",
                params![
                    conn.last_seen.timestamp(),
                    conn.state,
                    conn.bytes_sent as i64,
                    conn.bytes_recv as i64,
                    conn.app_protocol.as_ref().map(protocol_to_string),
                    id
                ],
            )?;
            return Ok(());
        }

        self.conn.execute(
            "INSERT INTO connections (first_seen, last_seen, src_ip, src_port, dst_ip, dst_port, transport, app_protocol, state, bytes_sent, bytes_recv) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                conn.first_seen.timestamp(),
                conn.last_seen.timestamp(),
                conn.src_ip.to_string(),
                conn.src_port as i64,
                conn.dst_ip.to_string(),
                conn.dst_port as i64,
                conn.transport.to_string(),
                conn.app_protocol.as_ref().map(protocol_to_string),
                conn.state,
                conn.bytes_sent as i64,
                conn.bytes_recv as i64
            ],
        )?;
        conn.id = Some(self.conn.last_insert_rowid());
        Ok(())
    }

    pub fn mark_connection_closed(&self, key: &ConnectionKey) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE connections SET state = 'CLOSED', last_seen = ? WHERE src_ip = ? AND src_port = ? AND dst_ip = ? AND dst_port = ? AND transport = ?",
            params![
                Utc::now().timestamp(),
                key.src_ip.to_string(),
                key.src_port as i64,
                key.dst_ip.to_string(),
                key.dst_port as i64,
                key.protocol.to_string()
            ],
        )?;
        Ok(())
    }

    pub fn insert_http_request(&self, connection_id: i64, req: &HttpRequest) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO http_requests (connection_id, ts, method, host, path, http_version, authorization, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                connection_id,
                req.ts.timestamp(),
                req.method,
                req.host,
                req.path,
                req.http_version,
                req.authorization,
                req.user_agent
            ],
        )?;
        Ok(())
    }

    pub fn insert_scan_result(&self, scan: &ScanResult) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO scans (dst_ip, ts, status, ports, result_raw) VALUES (?, ?, ?, ?, ?)",
            params![
                scan.dst_ip.to_string(),
                scan.ts.timestamp(),
                scan.status.to_string(),
                scan.ports,
                scan.result_raw
            ],
        )?;
        Ok(())
    }

    pub fn upsert_endpoint(&self, info: &EndpointInfo) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO endpoint_info (ip, country, city, latitude, longitude, hostname, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET country=excluded.country, city=excluded.city, latitude=excluded.latitude, longitude=excluded.longitude, hostname=excluded.hostname, last_updated=excluded.last_updated",
            params![
                info.ip.to_string(),
                info.country,
                info.city,
                info.latitude,
                info.longitude,
                info.hostname,
                info.last_updated.map(|ts| ts.timestamp())
            ],
        )?;
        Ok(())
    }

    pub fn recent_connections(&self, limit: usize) -> anyhow::Result<Vec<Connection>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, first_seen, last_seen, src_ip, src_port, dst_ip, dst_port, transport, app_protocol, state, bytes_sent, bytes_recv FROM connections ORDER BY last_seen DESC LIMIT ?",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let transport: String = row.get(7)?;
            let app_protocol: Option<String> = row.get(8)?;
            Ok(Connection {
                id: row.get(0)?,
                first_seen: ts_to_dt(row.get::<_, i64>(1)?),
                last_seen: ts_to_dt(row.get::<_, i64>(2)?),
                src_ip: row.get::<_, String>(3)?.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
                src_port: row.get::<_, i64>(4)? as u16,
                dst_ip: row.get::<_, String>(5)?.parse().unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
                dst_port: row.get::<_, i64>(6)? as u16,
                transport: parse_transport(&transport),
                app_protocol: app_protocol.map(parse_app_protocol),
                state: row.get(9)?,
                bytes_sent: row.get::<_, i64>(10)? as u64,
                bytes_recv: row.get::<_, i64>(11)? as u64,
                direction: crate::model::ConnectionDirection::Unknown,
            })
        })?;

        let mut res = Vec::new();
        for row in rows {
            if let Ok(conn) = row {
                res.push(conn);
            }
        }
        Ok(res)
    }
}

fn ts_to_dt(ts: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(ts, 0).single().unwrap_or_else(Utc::now)
}

fn protocol_to_string(proto: &ApplicationProtocol) -> String {
    match proto {
        ApplicationProtocol::Http => "HTTP".into(),
        ApplicationProtocol::Https => "HTTPS".into(),
        ApplicationProtocol::Ssh => "SSH".into(),
        ApplicationProtocol::Other(v) => v.clone(),
        ApplicationProtocol::Unknown => "UNKNOWN".into(),
    }
}

fn parse_app_protocol(value: String) -> ApplicationProtocol {
    match value.as_str() {
        "HTTP" => ApplicationProtocol::Http,
        "HTTPS" => ApplicationProtocol::Https,
        "SSH" => ApplicationProtocol::Ssh,
        "UNKNOWN" => ApplicationProtocol::Unknown,
        other => ApplicationProtocol::Other(other.to_string()),
    }
}

fn parse_transport(value: &str) -> TransportProtocol {
    match value {
        "TCP" => TransportProtocol::Tcp,
        "UDP" => TransportProtocol::Udp,
        other => TransportProtocol::Other(other.to_string()),
    }
}

impl std::fmt::Display for ScanStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanStatus::Pending => write!(f, "PENDING"),
            ScanStatus::Running => write!(f, "RUNNING"),
            ScanStatus::Done => write!(f, "DONE"),
            ScanStatus::Failed => write!(f, "FAILED"),
        }
    }
}
