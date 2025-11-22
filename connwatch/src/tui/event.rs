use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    Quit,
    Up,
    Down,
    NextPane,
    None,
}

pub fn poll_input(timeout: Duration) -> anyhow::Result<Option<InputEvent>> {
    if !event::poll(timeout)? {
        return Ok(None);
    }
    if let Event::Key(key) = event::read()? {
        if key.kind == KeyEventKind::Press {
            let evt = match key.code {
                KeyCode::Char('q') | KeyCode::Char('c') if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL) => {
                    InputEvent::Quit
                }
                KeyCode::Char('q') => InputEvent::Quit,
                KeyCode::Down | KeyCode::Char('j') => InputEvent::Down,
                KeyCode::Up | KeyCode::Char('k') => InputEvent::Up,
                KeyCode::Tab => InputEvent::NextPane,
                _ => InputEvent::None,
            };
            return Ok(Some(evt));
        }
    }
    Ok(None)
}
