use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use connwatch::model::{Connection, ConnectionDirection, ConnectionKey, TransportProtocol};
use connwatch::storage::Storage;

fn temp_db_path() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("connwatch-test-{nanos}.db"))
}

#[test]
fn schema_and_connection_roundtrip() {
    let path = temp_db_path();
    let storage = Storage::new(&path).expect("db created");
    storage.init_schema().expect("schema created");

    let key = ConnectionKey {
        src_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        src_port: 10000,
        dst_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
        dst_port: 80,
        protocol: TransportProtocol::Tcp,
    };
    let mut conn = Connection::new(key, ConnectionDirection::Outgoing);
    storage
        .insert_or_update_connection(&mut conn)
        .expect("insert works");
    assert!(conn.id.is_some());
    std::fs::remove_file(&path).ok();
}
