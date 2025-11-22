use std::f32::consts::PI;
use std::net::IpAddr;

use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};

use globe::{Canvas, GlobeConfig, GlobeTemplate};

use crate::model::EndpointInfo;

/// Render a lightweight ASCII globe placeholder.
pub fn render(
    markers: &[EndpointInfo],
    tick: u64,
    selected: Option<IpAddr>,
    width: u16,
    height: u16,
) -> Paragraph<'static> {
    // Fill the column with a near-square aspect.
    let inner_w = width.max(10);
    let inner_h = height.max(10);

    let mut canvas = Canvas::new(inner_w, inner_h, Some((1, 1)));
    let mut globe = GlobeConfig::new()
        .use_template(GlobeTemplate::Earth)
        .build();
    globe.angle = (tick as f32) * 0.08;
    globe.render_on(&mut canvas);

    let rotation_deg = globe.angle * 180.0 / PI;
    for ep in markers {
        if let (Some(lat), Some(lon)) = (ep.latitude, ep.longitude) {
            let (x, y) = lat_lon_to_canvas(lat as f32, lon as f32, rotation_deg, &canvas);
            let marker = if selected.is_some() && selected.unwrap() == ep.ip {
                'X'
            } else {
                marker_symbol(tick)
            };
            if y < canvas.matrix.len() && x < canvas.matrix[0].len() {
                canvas.matrix[y][x] = marker;
            }
        }
    }

    let lines = canvas
        .matrix
        .into_iter()
        .map(|row| Line::from(row.iter().collect::<String>()))
        .collect::<Vec<_>>();

    Paragraph::new(lines).block(Block::default().title("Globe").borders(Borders::ALL))
}

fn marker_symbol(tick: u64) -> char {
    match tick % 4 {
        0 => 'o',
        1 => '*',
        2 => '.',
        _ => '+',
    }
}

fn lat_lon_to_canvas(lat: f32, lon: f32, rotation_deg: f32, canvas: &Canvas) -> (usize, usize) {
    let width = canvas.get_size().0.max(1) as f32;
    let height = canvas.get_size().1.max(1) as f32;
    let mut lon_adj = lon + rotation_deg;
    while lon_adj > 180.0 {
        lon_adj -= 360.0;
    }
    while lon_adj < -180.0 {
        lon_adj += 360.0;
    }
    let x = ((lon_adj + 180.0) / 360.0 * (width - 1.0)).clamp(0.0, width - 1.0);
    let y = ((90.0 - lat) / 180.0 * (height - 1.0)).clamp(0.0, height - 1.0);
    (x as usize, y as usize)
}
