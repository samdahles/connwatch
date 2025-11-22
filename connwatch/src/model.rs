use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Other(String),
}

impl std::fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportProtocol::Tcp => write!(f, "TCP"),
            TransportProtocol::Udp => write!(f, "UDP"),
            TransportProtocol::Other(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ApplicationProtocol {
    Http,
    Https,
    Ssh,
    Other(String),
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConnectionDirection {
    Incoming,
    Outgoing,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Connection {
    pub id: Option<i64>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub transport: TransportProtocol,
    pub app_protocol: Option<ApplicationProtocol>,
    pub state: String,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub direction: ConnectionDirection,
}

impl Connection {
    pub fn new(key: ConnectionKey, direction: ConnectionDirection) -> Self {
        let now = Utc::now();
        Connection {
            id: None,
            first_seen: now,
            last_seen: now,
            src_ip: key.src_ip,
            src_port: key.src_port,
            dst_ip: key.dst_ip,
            dst_port: key.dst_port,
            transport: key.protocol,
            app_protocol: None,
            state: "OPEN".to_string(),
            bytes_sent: 0,
            bytes_recv: 0,
            direction,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConnectionEvent {
    Opened(Connection),
    Updated(Connection),
    Closed(ConnectionKey),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpRequest {
    pub ts: DateTime<Utc>,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub http_version: Option<String>,
    pub authorization: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointInfo {
    pub ip: IpAddr,
    pub country: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub hostname: Option<String>,
    pub last_updated: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanStatus {
    Pending,
    Running,
    Done,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub dst_ip: IpAddr,
    pub ts: DateTime<Utc>,
    pub status: ScanStatus,
    pub ports: Option<String>,
    pub result_raw: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionView {
    pub key: ConnectionKey,
    pub direction: ConnectionDirection,
    pub state: String,
    pub last_seen: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub app_protocol: Option<ApplicationProtocol>,
}

impl From<&Connection> for ConnectionView {
    fn from(conn: &Connection) -> Self {
        ConnectionView {
            key: ConnectionKey {
                src_ip: conn.src_ip,
                src_port: conn.src_port,
                dst_ip: conn.dst_ip,
                dst_port: conn.dst_port,
                protocol: conn.transport.clone(),
            },
            direction: conn.direction.clone(),
            state: conn.state.clone(),
            last_seen: conn.last_seen,
            bytes_sent: conn.bytes_sent,
            bytes_recv: conn.bytes_recv,
            app_protocol: conn.app_protocol.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ConnectionState {
    pub connection: Connection,
    pub last_packet_ts: SystemTime,
}

pub enum AppEvent {
    ConnectionAdded(ConnectionView),
    ConnectionUpdated(ConnectionView),
    ConnectionClosed(ConnectionKey),
    EndpointUpdated(EndpointInfo),
    ScanUpdated(ScanResult),
}
