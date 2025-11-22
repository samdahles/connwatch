use ratatui::layout::{Constraint, Direction, Layout, Rect};

use crate::config::Config;

#[derive(Debug)]
pub struct LayoutChunks {
    pub globe: Option<Rect>,
    pub list: Option<Rect>,
    pub detail: Option<Rect>,
}

pub fn split(area: Rect, config: &Config) -> LayoutChunks {
    // Two-column layout:
    // Left: globe (40% if enabled)
    // Right: stacked list (top) and detail (bottom)
    let mut globe = None;
    let mut list = None;
    let mut detail = None;

    let (left_rect, right_rect) = if config.show_globe {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);
        (Some(chunks[0]), chunks[1])
    } else {
        (None, area)
    };

    if let Some(left) = left_rect {
        globe = Some(left);
    }

    // Vertical split inside right column.
    match (config.show_list, config.show_detail) {
        (true, true) => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(right_rect);
            list = Some(rows[0]);
            detail = Some(rows[1]);
        }
        (true, false) => {
            list = Some(right_rect);
        }
        (false, true) => {
            detail = Some(right_rect);
        }
        (false, false) => {}
    }

    LayoutChunks { globe, list, detail }
}
