use std::path::PathBuf;

use clap::{ArgAction, Parser};
use directories::BaseDirs;

/// Application configuration parsed from CLI flags.
#[derive(Clone, Debug, Parser)]
#[command(name = "connwatch", version, about = "Terminal network connection monitor")]
pub struct Config {
    /// Network interface to capture on.
    #[arg(long, short = 'i')]
    pub interface: Option<String>,

    /// Optional offline pcap file for development and testing.
    #[arg(long)]
    pub pcap_file: Option<PathBuf>,

    /// Custom BPF filter for capture.
    #[arg(long)]
    pub pcap_filter: Option<String>,

    /// Path to SQLite database.
    #[arg(long, value_name = "PATH")]
    pub db_path: Option<PathBuf>,

    /// Disable globe column.
    #[arg(long = "no-globe", action = ArgAction::SetFalse, default_value_t = true)]
    pub show_globe: bool,

    /// Disable list column.
    #[arg(long = "no-list", action = ArgAction::SetFalse, default_value_t = true)]
    pub show_list: bool,

    /// Disable detail column.
    #[arg(long = "no-detail", action = ArgAction::SetFalse, default_value_t = true)]
    pub show_detail: bool,

    /// Enable Nmap scanning of remote hosts.
    #[arg(long)]
    pub enable_nmap: bool,

    /// Ports to pass to Nmap.
    #[arg(long, default_value = "22,80,443,8080")]
    pub nmap_ports: String,

    /// MaxMind database path for geolocation.
    #[arg(long)]
    pub mmdb_path: Option<PathBuf>,

    /// Logging level (info, debug, trace).
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Whether to store Authorization headers.
    #[arg(long, action = ArgAction::SetTrue, default_value_t = false)]
    pub log_auth_headers: bool,
}

fn default_db_path() -> PathBuf {
    if let Some(base) = BaseDirs::new() {
        let mut path = base.data_dir().to_path_buf();
        path.push("connwatch");
        path.push("connwatch.db");
        return path;
    }
    PathBuf::from(".local/share/connwatch/connwatch.db")
}

impl Config {
    pub fn from_cli() -> Self {
        let mut cfg = Self::parse();
        if cfg.db_path.is_none() {
            cfg.db_path = Some(default_db_path());
        }
        cfg
    }
}
