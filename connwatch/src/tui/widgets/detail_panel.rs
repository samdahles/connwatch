use std::net::IpAddr;
use std::process::Command;

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::tui::AppState;

pub fn render(f: &mut Frame<'_>, area: Rect, state: &mut AppState) {
    let Some(conn) = state.connections.get(state.selected_index) else {
        let empty = Paragraph::new("No selection")
            .block(Block::default().title("Details").borders(Borders::ALL));
        f.render_widget(empty, area);
        return;
    };

    let ipinfo = state
        .selected_remote_ip()
        .and_then(|ip| maybe_ipinfo(ip, &mut state.ipinfo_cache));

    let lines = vec![
        Line::from(format!("State: {}", conn.state)),
        Line::from(format!(
            "Local: {}:{}",
            conn.key.src_ip, conn.key.src_port
        )),
        Line::from(format!(
            "Remote: {}:{}",
            conn.key.dst_ip, conn.key.dst_port
        )),
        Line::from(format!(
            "Protocol: {}",
            conn.app_protocol
                .as_ref()
                .map(|p| format!("{:?}", p))
                .unwrap_or_else(|| conn.key.protocol.to_string())
        )),
        Line::from(format!(
            "Bytes sent/recv: {}/{}",
            conn.bytes_sent, conn.bytes_recv
        )),
        Line::from(format!(
            "Last seen: {}",
            chrono::Utc::now()
                .signed_duration_since(conn.last_seen)
                .num_seconds()
        )),
    ]
    .into_iter()
    .chain(
        ipinfo
            .as_ref()
            .map(|info| info.lines().map(|l| Line::from(l.to_string())))
            .into_iter()
            .flatten(),
    )
    .collect::<Vec<_>>();

    let para = Paragraph::new(lines)
        .style(Style::default().fg(Color::White))
        .block(Block::default().title(Span::styled("Details", Style::default().fg(Color::Magenta))).borders(Borders::ALL));
    f.render_widget(para, area);
}

fn maybe_ipinfo(ip: IpAddr, cache: &mut std::collections::HashMap<IpAddr, String>) -> Option<String> {
    if !is_private_ip(ip) {
        return None;
    }
    if let Some(cached) = cache.get(&ip) {
        return Some(cached.clone());
    }
    let output = Command::new("ipinfo").arg(ip.to_string()).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        return None;
    }
    cache.insert(ip, text.clone());
    Some(text)
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.segments()[0] & 0xfe00 == 0xfc00, // simple ULA check
    }
}
