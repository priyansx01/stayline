//! Tray icons drawn at runtime: a coloured dot per state.

use tray_icon::Icon;

const SIZE: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Light {
    Off,
    Busy,
    On,
    Alert,
}

impl Light {
    fn rgb(self) -> [u8; 3] {
        match self {
            Light::Off => [140, 140, 140],
            Light::Busy => [235, 165, 20],
            Light::On => [35, 170, 85],
            Light::Alert => [215, 55, 55],
        }
    }
}

/// A filled, anti-aliased circle with a darker rim.
pub fn icon(light: Light) -> Icon {
    let [r, g, b] = light.rgb();
    let rim = [r / 2, g / 2, b / 2];
    let centre = (SIZE as f32 - 1.0) / 2.0;
    let radius = SIZE as f32 / 2.0 - 1.5;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let d = ((x as f32 - centre).powi(2) + (y as f32 - centre).powi(2)).sqrt();
            let alpha = (radius + 0.5 - d).clamp(0.0, 1.0);
            let colour = if d > radius - 2.5 { rim } else { [r, g, b] };
            rgba.extend_from_slice(&colour);
            rgba.push((alpha * 255.0) as u8);
        }
    }
    Icon::from_rgba(rgba, SIZE, SIZE).expect("icon dimensions match buffer")
}
