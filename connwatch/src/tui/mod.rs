use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::collections::HashMap;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::model::{AppEvent, ConnectionKey, ConnectionView, EndpointInfo};
use crate::storage::Storage;

pub mod event;
pub mod layout;
pub mod widgets;

use event::InputEvent;

pub type SharedStorage = Arc<Mutex<Storage>>;

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = restore_terminal();
    }
}

pub struct AppState {
    pub connections: Vec<ConnectionView>,
    pub endpoints: Vec<EndpointInfo>,
    pub ipinfo_cache: HashMap<std::net::IpAddr, String>,
    pub selected_index: usize,
    pub show_globe: bool,
    pub show_list: bool,
    pub show_detail: bool,
    pub ticks: u64,
}

impl AppState {
    pub fn new(config: &Config) -> Self {
        Self {
            connections: Vec::new(),
            endpoints: Vec::new(),
            ipinfo_cache: HashMap::new(),
            selected_index: 0,
            show_globe: config.show_globe,
            show_list: config.show_list,
            show_detail: config.show_detail,
            ticks: 0,
        }
    }

    pub fn selected_remote_ip(&self) -> Option<std::net::IpAddr> {
        let conn = self.connections.get(self.selected_index)?;
        Some(match conn.direction {
            crate::model::ConnectionDirection::Outgoing => conn.key.dst_ip,
            crate::model::ConnectionDirection::Incoming => conn.key.src_ip,
            crate::model::ConnectionDirection::Unknown => conn.key.dst_ip,
        })
    }

    pub fn apply_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::ConnectionAdded(view) => {
                self.connections.insert(0, view);
            }
            AppEvent::ConnectionUpdated(view) => {
                if let Some(idx) = self
                    .connections
                    .iter()
                    .position(|c| same_key(&c.key, &view.key))
                {
                    self.connections[idx] = view;
                } else {
                    self.connections.insert(0, view);
                }
            }
            AppEvent::ConnectionClosed(key) => {
                self.connections.retain(|c| !same_key(&c.key, &key));
                if self.selected_index >= self.connections.len() {
                    self.selected_index = self.connections.len().saturating_sub(1);
                }
            }
            AppEvent::EndpointUpdated(info) => {
                if let Some(ep) = self.endpoints.iter_mut().find(|e| e.ip == info.ip) {
                    *ep = info;
                } else {
                    self.endpoints.push(info);
                }
            }
            AppEvent::ScanUpdated(_) => {
                // detail panel can pick it up from storage; nothing to do for now.
            }
        }
    }
}

fn same_key(a: &ConnectionKey, b: &ConnectionKey) -> bool {
    a.src_ip == b.src_ip
        && a.dst_ip == b.dst_ip
        && a.src_port == b.src_port
        && a.dst_port == b.dst_port
        && a.protocol == b.protocol
}

pub async fn run_app(
    config: Config,
    _storage: SharedStorage,
    mut event_rx: mpsc::Receiver<AppEvent>,
    shutdown: watch::Sender<bool>,
) -> anyhow::Result<()> {
    setup_terminal()?;
    let _guard = TerminalGuard;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    let mut state = AppState::new(&config);

    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    loop {
        tokio::select! {
            maybe_evt = event_rx.recv() => {
                if let Some(evt) = maybe_evt {
                    state.apply_event(evt);
                }
            }
            _ = ticker.tick() => {
                state.ticks = state.ticks.wrapping_add(1);
                if let Some(input) = event::poll_input(Duration::from_millis(0))? {
                    if handle_input(input, &mut state) {
                        break;
                    }
                }
                terminal.draw(|f| draw(f, &config, &mut state)).context("failed to draw ui")?;
            }
        }
    }

    shutdown.send(true).ok();
    Ok(())
}

fn handle_input(input: InputEvent, state: &mut AppState) -> bool {
    match input {
        InputEvent::Quit => return true,
        InputEvent::Down => {
            if !state.connections.is_empty() {
                state.selected_index = (state.selected_index + 1).min(state.connections.len() - 1);
            }
        }
        InputEvent::Up => {
            if !state.connections.is_empty() {
                state.selected_index = state.selected_index.saturating_sub(1);
            }
        }
        InputEvent::NextPane => {
            // placeholder for focus switching
        }
        InputEvent::None => {}
    }
    false
}

fn draw(f: &mut ratatui::Frame<'_>, config: &Config, state: &mut AppState) {
    let layout = layout::split(f.size(), config);
    if let Some(area) = layout.globe {
        if state.show_globe {
            widgets::globe_widget::render(f, area, state);
        }
    }
    if let Some(area) = layout.list {
        if state.show_list {
            widgets::connection_list::render(f, area, state);
        }
    }
    if let Some(area) = layout.detail {
        if state.show_detail {
            widgets::detail_panel::render(f, area, state);
        }
    }
}

fn setup_terminal() -> anyhow::Result<()> {
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen)?;
    Ok(())
}

fn restore_terminal() -> anyhow::Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}
