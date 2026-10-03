#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
#[cfg(windows)]
mod client;
#[cfg(windows)]
mod format;
#[cfg(windows)]
mod icons;
#[cfg(windows)]
mod instance;
#[cfg(windows)]
mod service_ctl;
#[cfg(windows)]
mod theme;

fn main() {
    #[cfg(windows)]
    app::main();
}
