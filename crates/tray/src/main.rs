#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
#[cfg(windows)]
mod client;
#[cfg(windows)]
mod icons;

fn main() {
    #[cfg(windows)]
    app::main();
}
