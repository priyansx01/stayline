//! "Start stayline when I sign in" via the current user's Run key.

use auto_launch::{AutoLaunch, WindowsEnableMode};

/// Argument passed when Windows starts the tray at sign-in, so it starts
/// quietly in the tray instead of opening its window.
pub const BACKGROUND_ARG: &str = "--background";

fn launcher() -> Option<AutoLaunch> {
    let exe = std::env::current_exe().ok()?;
    Some(AutoLaunch::new(
        "stayline",
        exe.to_str()?,
        WindowsEnableMode::CurrentUser,
        &[BACKGROUND_ARG],
    ))
}

pub fn is_enabled() -> bool {
    launcher()
        .and_then(|l| l.is_enabled().ok())
        .unwrap_or(false)
}

pub fn set(enabled: bool) -> Result<(), String> {
    let launcher = launcher().ok_or("cannot find the stayline executable")?;
    let result = if enabled {
        launcher.enable()
    } else {
        launcher.disable()
    };
    result.map_err(|e| format!("could not change the sign-in setting: {e}"))
}
