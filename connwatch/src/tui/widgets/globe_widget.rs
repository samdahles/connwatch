use ratatui::layout::Rect;
use ratatui::Frame;

use crate::globe_view;
use crate::tui::AppState;

pub fn render(f: &mut Frame<'_>, area: Rect, state: &AppState) {
    let globe = globe_view::render(
        &state.endpoints,
        state.ticks,
        state.selected_remote_ip(),
        area.width.saturating_sub(2),
        area.height.saturating_sub(2),
    );
    f.render_widget(globe, area);
}
