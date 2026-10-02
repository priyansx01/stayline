//! Icons drawn at runtime: a coloured dot per state.

use tray_icon::Icon;

pub const SIZE: u32 = 32;

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

    /// Index used by the UI's status dot.
    pub fn kind(self) -> i32 {
        match self {
            Light::Off => 0,
            Light::Busy => 1,
            Light::On => 2,
            Light::Alert => 3,
        }
    }
}

/// RGBA pixels of a filled, anti-aliased circle with a darker rim.
pub fn rgba(light: Light) -> Vec<u8> {
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
    rgba
}

pub fn tray_icon(light: Light) -> Icon {
    Icon::from_rgba(rgba(light), SIZE, SIZE).expect("icon dimensions match buffer")
}

pub fn window_icon(light: Light) -> slint::Image {
    let buffer =
        slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(&rgba(light), SIZE, SIZE);
    slint::Image::from_rgba8(buffer)
}
