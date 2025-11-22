mod analysis;
mod capture;
mod config;
mod globe_view;
mod model;
mod nmap;
mod storage;
mod tui;

use std::sync::{Arc, Mutex};

use config::Config;
use storage::Storage;
use tokio::sync::{mpsc, watch};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_cli();
    init_tracing(&config);
    tracing::info!("starting connwatch");

    let storage = Storage::new(
        config
            .db_path
            .as_ref()
            .expect("db path should be set after parsing"),
    )?;
    storage.init_schema()?;
    let storage = Arc::new(Mutex::new(storage));

    let (event_tx, event_rx) = mpsc::channel(1024);
    let (scan_tx, scan_rx) = mpsc::channel(64);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    if config.enable_nmap {
        nmap::spawn_worker(
            config.clone(),
            storage.clone(),
            scan_rx,
            shutdown_rx.clone(),
            event_tx.clone(),
        );
    }

    capture::spawn_capture(
        config.clone(),
        storage.clone(),
        event_tx.clone(),
        scan_tx,
        shutdown_rx.clone(),
    );

    tui::run_app(config, storage, event_rx, shutdown_tx).await?;

    tracing::info!("connwatch exited");
    Ok(())
}

fn init_tracing(config: &Config) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
