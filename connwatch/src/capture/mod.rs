use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use chrono::Utc;
use pcap::Capture;
use maxminddb::geoip2::City;
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use tokio::sync::{mpsc, watch};

use crate::analysis;
use crate::config::Config;
use crate::model::{
    AppEvent, ApplicationProtocol, Connection, ConnectionDirection, ConnectionKey, ConnectionState,
    ConnectionView, EndpointInfo, TransportProtocol,
};
use crate::storage::Storage;

pub type SharedStorage = Arc<Mutex<Storage>>;

pub fn spawn_capture(
    config: Config,
    storage: SharedStorage,
    event_tx: mpsc::Sender<AppEvent>,
    scan_tx: mpsc::Sender<IpAddr>,
    shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let local_ips = collect_local_ips(&config.interface);
        let mut state = HashMap::<ConnectionKey, ConnectionState>::new();

        // Run capture in a blocking context so we do not block the async runtime.
        let res = tokio::task::spawn_blocking(move || {
            let mut shutdown_rx = shutdown.clone();
            if let Some(ref pcap_file) = config.pcap_file {
                run_capture(
                    Capture::from_file(pcap_file).map_err(anyhow::Error::from),
                    &local_ips,
                    &storage,
                    &event_tx,
                    &scan_tx,
                    &mut state,
                    &config,
                    &shutdown_rx,
                )
            } else {
                let mut shutdown_rx = shutdown.clone();
                let device = select_device(config.interface.as_deref());
                let cap = device.and_then(|dev| {
                    Capture::from_device(dev)
                        .map_err(anyhow::Error::from)
                        .and_then(|builder| {
                            Ok(builder.promisc(true).snaplen(65535).open()?)
                        })
                });
                run_capture(
                    cap,
                    &local_ips,
                    &storage,
                    &event_tx,
                    &scan_tx,
                    &mut state,
                    &config,
                    &shutdown_rx,
                )
            }
        })
        .await;

        if let Err(err) = res {
            tracing::error!("capture task failed: {err:?}");
        }
    });
}

fn run_capture<T: pcap::Activated>(
    capture: Result<Capture<T>, anyhow::Error>,
    local_ips: &[IpAddr],
    storage: &SharedStorage,
    event_tx: &mpsc::Sender<AppEvent>,
    scan_tx: &mpsc::Sender<IpAddr>,
    state: &mut HashMap<ConnectionKey, ConnectionState>,
    config: &Config,
    shutdown: &watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut cap = match capture {
        Ok(cap) => cap,
        Err(err) => {
            tracing::warn!("pcap unavailable: {err:?}, running in mock mode");
            return Ok(());
        }
    };

    if let Some(filter) = &config.pcap_filter {
        if let Err(err) = cap.filter(filter, true) {
            tracing::warn!("failed to set custom filter {filter}: {err:?}");
        }
    } else if let Err(err) = cap.filter("tcp or udp", true) {
        tracing::warn!("failed to set default filter: {err:?}");
    }

    while let Ok(packet) = cap.next_packet() {
        if *shutdown.borrow() {
            break;
        }
        if let Some((key, payload)) = parse_packet(packet.data) {
            handle_packet(
                key,
                &payload,
                local_ips,
                storage,
                event_tx,
                scan_tx,
                state,
                config,
            );
        }
    }
    Ok(())
}

fn handle_packet(
    key: ConnectionKey,
    payload: &[u8],
    local_ips: &[IpAddr],
    storage: &SharedStorage,
    event_tx: &mpsc::Sender<AppEvent>,
    scan_tx: &mpsc::Sender<IpAddr>,
    state: &mut HashMap<ConnectionKey, ConnectionState>,
    config: &Config,
) {
    let direction = analysis::infer_direction(local_ips, key.src_ip, key.dst_ip);
    let now = SystemTime::now();
    let mut app_proto = analysis::detect_application_protocol(
        key.src_port,
        key.dst_port,
        payload,
    );

    if let Some(existing) = state.get_mut(&key) {
        existing.connection.last_seen = Utc::now();
        update_counters(&mut existing.connection, direction.clone(), payload.len() as u64);
        if existing.connection.app_protocol.is_none() {
            existing.connection.app_protocol = app_proto.clone();
        }
        let mut conn_view = ConnectionView::from(&existing.connection);
        if let Some(proto) = app_proto.take() {
            conn_view.app_protocol = Some(proto);
        }
        let _ = event_tx.blocking_send(AppEvent::ConnectionUpdated(conn_view));
        if let Ok(db) = storage.lock() {
            let _ = db.insert_or_update_connection(&mut existing.connection);
        }
        return;
    }

    let mut connection = Connection::new(key.clone(), direction.clone());
    update_counters(&mut connection, direction.clone(), payload.len() as u64);
    if app_proto.is_none() {
        app_proto = analysis::detect_application_protocol(key.src_port, key.dst_port, payload);
    }
    connection.app_protocol = app_proto.clone();

    let mut conn_state = ConnectionState {
        connection,
        last_packet_ts: now,
    };
    if let Ok(db) = storage.lock() {
        let _ = db.insert_or_update_connection(&mut conn_state.connection);
    }

    if let Some(proto) = app_proto {
        if proto == ApplicationProtocol::Http {
            if let Some(id) = conn_state.connection.id {
                if let Some(http) = analysis::parse_http_request(payload, config.log_auth_headers) {
                    if let Ok(db) = storage.lock() {
                        let _ = db.insert_http_request(id, &http);
                    }
                }
            }
        }
    }

    let remote_ip = match direction {
        ConnectionDirection::Outgoing => key.dst_ip,
        ConnectionDirection::Incoming => key.src_ip,
        ConnectionDirection::Unknown => key.dst_ip,
    };
    if let Some(path) = config.mmdb_path.as_deref() {
        if let Some(endpoint) = lookup_geolocation(path, remote_ip) {
            if let Ok(db) = storage.lock() {
                let _ = db.upsert_endpoint(&endpoint);
            }
            let _ = event_tx.blocking_send(AppEvent::EndpointUpdated(endpoint));
        }
    }
    let view = ConnectionView::from(&conn_state.connection);
    let _ = event_tx.blocking_send(AppEvent::ConnectionAdded(view));
    let _ = scan_tx.try_send(remote_ip);
    state.insert(key, conn_state);
}

fn update_counters(conn: &mut Connection, direction: ConnectionDirection, bytes: u64) {
    match direction {
        ConnectionDirection::Outgoing => conn.bytes_sent += bytes,
        ConnectionDirection::Incoming => conn.bytes_recv += bytes,
        ConnectionDirection::Unknown => {
            conn.bytes_sent += bytes / 2;
            conn.bytes_recv += bytes / 2;
        }
    }
}

fn parse_packet(data: &[u8]) -> Option<(ConnectionKey, Vec<u8>)> {
    let eth = EthernetPacket::new(data)?;
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => parse_ipv4_packet(eth.payload()),
        EtherTypes::Ipv6 => parse_ipv6_packet(eth.payload()),
        _ => None,
    }
}

fn parse_ipv4_packet(payload: &[u8]) -> Option<(ConnectionKey, Vec<u8>)> {
    let packet = Ipv4Packet::new(payload)?;
    let src_ip = IpAddr::V4(packet.get_source());
    let dst_ip = IpAddr::V4(packet.get_destination());
    match packet.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(packet.payload())?;
            let payload = tcp.payload().to_vec();
            Some((
                ConnectionKey {
                    src_ip,
                    dst_ip,
                    src_port: tcp.get_source(),
                    dst_port: tcp.get_destination(),
                    protocol: TransportProtocol::Tcp,
                },
                payload,
            ))
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(packet.payload())?;
            let payload = udp.payload().to_vec();
            Some((
                ConnectionKey {
                    src_ip,
                    dst_ip,
                    src_port: udp.get_source(),
                    dst_port: udp.get_destination(),
                    protocol: TransportProtocol::Udp,
                },
                payload,
            ))
        }
        _ => None,
    }
}

fn parse_ipv6_packet(payload: &[u8]) -> Option<(ConnectionKey, Vec<u8>)> {
    let packet = Ipv6Packet::new(payload)?;
    let src_ip = IpAddr::V6(packet.get_source());
    let dst_ip = IpAddr::V6(packet.get_destination());
    match packet.get_next_header() {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(packet.payload())?;
            let payload = tcp.payload().to_vec();
            Some((
                ConnectionKey {
                    src_ip,
                    dst_ip,
                    src_port: tcp.get_source(),
                    dst_port: tcp.get_destination(),
                    protocol: TransportProtocol::Tcp,
                },
                payload,
            ))
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(packet.payload())?;
            let payload = udp.payload().to_vec();
            Some((
                ConnectionKey {
                    src_ip,
                    dst_ip,
                    src_port: udp.get_source(),
                    dst_port: udp.get_destination(),
                    protocol: TransportProtocol::Udp,
                },
                payload,
            ))
        }
        _ => None,
    }
}

fn lookup_geolocation(path: &Path, ip: IpAddr) -> Option<EndpointInfo> {
    let reader = maxminddb::Reader::open_readfile(path).ok()?;
    let city: City = reader.lookup(ip).ok()?;
    let location = city.location?;
    let country = city
        .country
        .as_ref()
        .and_then(|c| c.names.as_ref())
        .and_then(|names| names.get("en"))
        .map(|s| s.to_string());
    let city_name = city
        .city
        .as_ref()
        .and_then(|c| c.names.as_ref())
        .and_then(|names| names.get("en"))
        .map(|s| s.to_string());
    Some(EndpointInfo {
        ip,
        country,
        city: city_name,
        latitude: location.latitude,
        longitude: location.longitude,
        hostname: None,
        last_updated: Some(Utc::now()),
    })
}

fn select_device(interface: Option<&str>) -> anyhow::Result<pcap::Device> {
    let devices = pcap::Device::list()?;
    if let Some(name) = interface {
        devices
            .into_iter()
            .find(|d| d.name == name)
            .ok_or_else(|| anyhow::anyhow!("interface {name} not found"))
    } else {
        devices
            .into_iter()
            .find(|d| !d.name.contains("lo"))
            .or_else(|| pcap::Device::list().ok().and_then(|mut d| d.pop()))
            .ok_or_else(|| anyhow::anyhow!("no capture devices available"))
    }
}

fn collect_local_ips(interface: &Option<String>) -> Vec<IpAddr> {
    if let Ok(devices) = pcap::Device::list() {
        for dev in devices {
            if interface.as_deref().map(|i| i == dev.name).unwrap_or(false) {
                return dev.addresses.iter().map(|addr| addr.addr).collect();
            }
        }
    }
    Vec::new()
}

pub fn expire_idle(
    state: &mut HashMap<ConnectionKey, ConnectionState>,
    idle_tcp: Duration,
    idle_udp: Duration,
    storage: &SharedStorage,
    event_tx: &mpsc::Sender<AppEvent>,
) {
    let now = SystemTime::now();
    let mut to_remove = Vec::new();
    for (key, conn_state) in state.iter() {
        let elapsed = now.duration_since(conn_state.last_packet_ts).unwrap_or_default();
        let timeout = match conn_state.connection.transport {
            TransportProtocol::Tcp => idle_tcp,
            TransportProtocol::Udp => idle_udp,
            TransportProtocol::Other(_) => idle_udp,
        };
        if elapsed > timeout {
            to_remove.push(key.clone());
        }
    }

    for key in to_remove {
        if let Some(mut conn) = state.remove(&key) {
            conn.connection.state = "CLOSED".into();
            if let Ok(db) = storage.lock() {
                let _ = db.mark_connection_closed(&key);
            }
            let _ = event_tx.blocking_send(AppEvent::ConnectionClosed(key));
        }
    }
}
