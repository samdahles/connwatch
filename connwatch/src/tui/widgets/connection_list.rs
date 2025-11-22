use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use ratatui::Frame;

use crate::model::{ApplicationProtocol, ConnectionDirection};
use crate::tui::AppState;

pub fn render(f: &mut Frame<'_>, area: Rect, state: &AppState) {
    if state.connections.is_empty() {
        let empty = ratatui::widgets::Paragraph::new("No active connections yet")
            .block(Block::default().title("Connections").borders(Borders::ALL));
        f.render_widget(empty, area);
        return;
    }

    let header_cells = ["Dir", "Local", "Remote", "Proto", "Bytes", "Last"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Cyan)));
    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

    let rows = state.connections.iter().enumerate().map(|(idx, conn)| {
        let dir = match conn.direction {
            ConnectionDirection::Incoming => "IN",
            ConnectionDirection::Outgoing => "OUT",
            ConnectionDirection::Unknown => "?",
        };
        let local = format!("{}:{}", conn.key.src_ip, conn.key.src_port);
        let remote = format!("{}:{}", conn.key.dst_ip, conn.key.dst_port);
        let proto = format_protocol(conn.app_protocol.as_ref(), &conn.key);
        let bytes = format!("{}/{}", conn.bytes_sent, conn.bytes_recv);
        let last = format_relative(conn.last_seen.timestamp());
        let cells = vec![dir, &local, &remote, &proto, &bytes, &last]
            .into_iter()
            .map(|c| Cell::from(c.to_string()));
        let mut row = Row::new(cells);
        if idx == state.selected_index {
            row = row.style(Style::default().fg(Color::Yellow));
        }
        row
    });

    let widths = [
        ratatui::layout::Constraint::Length(4),
        ratatui::layout::Constraint::Length(22),
        ratatui::layout::Constraint::Length(22),
        ratatui::layout::Constraint::Length(10),
        ratatui::layout::Constraint::Length(12),
        ratatui::layout::Constraint::Length(12),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().title(Line::from("Connections")).borders(Borders::ALL));
    f.render_widget(table, area);
}

fn format_protocol(app: Option<&ApplicationProtocol>, key: &crate::model::ConnectionKey) -> String {
    let base = key.protocol.to_string();
    match app {
        Some(ApplicationProtocol::Http) => format!("{base}/HTTP"),
        Some(ApplicationProtocol::Https) => format!("{base}/HTTPS"),
        Some(ApplicationProtocol::Ssh) => format!("{base}/SSH"),
        Some(ApplicationProtocol::Other(name)) => format!("{base}/{name}"),
        Some(ApplicationProtocol::Unknown) | None => base,
    }
}

fn format_relative(timestamp: i64) -> String {
    let now = chrono::Utc::now().timestamp();
    let delta = now.saturating_sub(timestamp);
    if delta < 60 {
        format!("{delta}s ago")
    } else if delta < 3600 {
        format!("{}m ago", delta / 60)
    } else {
        format!("{}h ago", delta / 3600)
    }
}
