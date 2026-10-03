//! Windows theme detection and resolution.

use stayline_config::ThemePreference;
use windows::core::w;
use windows::Win32::System::Registry::{
    HKEY_CURRENT_USER, RegCloseKey, RegOpenKeyExW, RegQueryValueExW, KEY_READ, REG_DWORD,
};

/// Reads `AppsUseLightTheme` from the Windows registry.
/// Returns `true` if Windows is in dark mode, `false` if in light mode.
pub fn is_windows_dark_theme() -> bool {
    unsafe {
        let mut key = Default::default();
        let subkey = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize");
        if RegOpenKeyExW(HKEY_CURRENT_USER, subkey, Some(0), KEY_READ, &mut key).is_ok() {
            let mut value: u32 = 0;
            let mut size = std::mem::size_of::<u32>() as u32;
            let mut type_ = REG_DWORD;
            let res = RegQueryValueExW(
                key,
                w!("AppsUseLightTheme"),
                None,
                Some(&mut type_),
                Some(&mut value as *mut u32 as *mut u8),
                Some(&mut size),
            );
            let _ = RegCloseKey(key);
            if res.is_ok() {
                return value == 0; // 0 = dark mode, 1 = light mode
            }
        }
    }
    true // fallback default to dark mode
}

/// Resolves whether the app should render in dark mode based on the user's preference.
pub fn resolve_is_dark(preference: ThemePreference) -> bool {
    match preference {
        ThemePreference::System => is_windows_dark_theme(),
        ThemePreference::Dark => true,
        ThemePreference::Light => false,
    }
}
