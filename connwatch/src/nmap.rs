use std::net::IpAddr;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;

use crate::config::Config;
use crate::model::{AppEvent, ScanResult, ScanStatus};
use crate::storage::Storage;

pub type ScanQueue = mpsc::Receiver<IpAddr>;
pub type SharedStorage = Arc<Mutex<Storage>>;

pub fn spawn_worker(
    config: Config,
    storage: SharedStorage,
    mut rx: ScanQueue,
    mut shutdown: watch::Receiver<bool>,
    event_tx: mpsc::Sender<AppEvent>,
) {
    tokio::spawn(async move {
        loop {
            let next_ip = tokio::select! {
                _ = shutdown.changed() => break,
                maybe_ip = rx.recv() => maybe_ip,
            };
            let Some(ip) = next_ip else {
                break;
            };
            let _ = run_scan(&config, ip, &storage, &event_tx).await;
            sleep(Duration::from_secs(5)).await;
        }
    });
}

async fn run_scan(
    config: &Config,
    ip: IpAddr,
    storage: &SharedStorage,
    event_tx: &mpsc::Sender<AppEvent>,
) -> anyhow::Result<()> {
    let mut record = ScanResult {
        dst_ip: ip,
        ts: Utc::now(),
        status: ScanStatus::Pending,
        ports: Some(config.nmap_ports.clone()),
        result_raw: None,
    };
    if let Ok(db) = storage.lock() {
        let _ = db.insert_scan_result(&record);
    }
    let _ = event_tx.send(AppEvent::ScanUpdated(record.clone())).await;

    let output = Command::new("nmap")
        .arg("-sC")
        .arg("-sV")
        .arg("-p")
        .arg(&config.nmap_ports)
        .arg("-oX")
        .arg("-")
        .arg(ip.to_string())
        .stdout(Stdio::piped())
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            record.status = ScanStatus::Done;
            record.result_raw = Some(String::from_utf8_lossy(&out.stdout).to_string());
        }
        Ok(out) => {
            record.status = ScanStatus::Failed;
            record.result_raw = Some(String::from_utf8_lossy(&out.stderr).to_string());
        }
        Err(err) => {
            record.status = ScanStatus::Failed;
            record.result_raw = Some(format!("failed to run nmap: {err}"));
        }
    }
    record.ts = Utc::now();
    if let Ok(db) = storage.lock() {
        let _ = db.insert_scan_result(&record);
    }
    let _ = event_tx.send(AppEvent::ScanUpdated(record)).await;
    Ok(())
}
