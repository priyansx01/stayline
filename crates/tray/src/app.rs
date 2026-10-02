//! Tray icon, menu and the Win32 message loop.

use std::sync::mpsc as std_mpsc;

use stayline_ipc::{Event, Request, TunnelState};
use stayline_tray::secret;
use stayline_tray::settings::{self, Settings};
use tauri_winrt_notification::Toast;
use tokio::sync::mpsc;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, LPARAM, WPARAM};
use windows::Win32::System::Threading::{CreateMutexW, GetCurrentThreadId};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, MSG, PostThreadMessageW, TranslateMessage, WM_APP,
};
use windows::core::w;

use crate::client::{self, FromService};
use crate::icons::{self, Light};

enum UiMessage {
    Menu(MenuId),
    Service(FromService),
}

pub fn main() {
    let _log = init_logging();
    if !single_instance() {
        return;
    }

    let mut app = match App::new() {
        Ok(app) => app,
        Err(e) => {
            tracing::error!(error = %e, "could not create the tray icon");
            return;
        }
    };

    // Other threads hand messages over a channel and post WM_APP to wake
    // this thread's message loop.
    let thread = unsafe { GetCurrentThreadId() };
    let wake = move || unsafe {
        let _ = PostThreadMessageW(thread, WM_APP, WPARAM(0), LPARAM(0));
    };
    let (ui_tx, ui_rx) = std_mpsc::channel::<UiMessage>();
    MenuEvent::set_event_handler(Some({
        let ui_tx = ui_tx.clone();
        move |event: MenuEvent| {
            let _ = ui_tx.send(UiMessage::Menu(event.id));
            wake();
        }
    }));
    app.requests = Some(client::start(move |message| {
        let _ = ui_tx.send(UiMessage::Service(message));
        wake();
    }));

    let mut msg = MSG::default();
    loop {
        // SAFETY: msg is a valid MSG; 0 means WM_QUIT, -1 an error.
        let got = unsafe { GetMessageW(&mut msg, None, 0, 0) };
        if got.0 <= 0 {
            break;
        }
        if msg.hwnd.0.is_null() && msg.message == WM_APP {
            while let Ok(message) = ui_rx.try_recv() {
                if !app.handle(message) {
                    return;
                }
            }
            continue;
        }
        // SAFETY: msg was filled by GetMessageW.
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

/// Menu items whose text or enabled state changes.
struct Items {
    status: MenuItem,
    connect: MenuItem,
    disconnect: MenuItem,
    forget: MenuItem,
}

struct App {
    tray: TrayIcon,
    items: Items,
    requests: Option<mpsc::UnboundedSender<Request>>,
    state: TunnelState,
    service_up: bool,
    /// Auto-connect is tried once per launch, on the first status received.
    auto_connect_checked: bool,
    service_warned: bool,
    last_alert: Option<String>,
}

impl App {
    fn new() -> anyhow::Result<Self> {
        let items = Items {
            status: MenuItem::with_id("status", "stayline: starting", false, None),
            connect: MenuItem::with_id("connect", "Connect", false, None),
            disconnect: MenuItem::with_id("disconnect", "Disconnect", false, None),
            forget: MenuItem::with_id("forget", "Forget saved password", secret::is_saved(), None),
        };
        let menu = Menu::new();
        menu.append_items(&[
            &items.status,
            &PredefinedMenuItem::separator(),
            &items.connect,
            &items.disconnect,
            &PredefinedMenuItem::separator(),
            &MenuItem::with_id("settings", "Edit settings…", true, None),
            &items.forget,
            &PredefinedMenuItem::separator(),
            &MenuItem::with_id("quit", "Quit tray (VPN stays up)", true, None),
        ])?;
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(icons::icon(Light::Off))
            .with_tooltip("stayline")
            .build()?;
        Ok(Self {
            tray,
            items,
            requests: None,
            state: TunnelState::Disconnected,
            service_up: false,
            auto_connect_checked: false,
            service_warned: false,
            last_alert: None,
        })
    }

    /// Returns `false` to quit.
    fn handle(&mut self, message: UiMessage) -> bool {
        match message {
            UiMessage::Menu(id) => match id.as_ref() {
                "connect" => self.connect(),
                "disconnect" => self.send(Request::Disconnect),
                "settings" => open_settings(),
                "forget" => match secret::forget() {
                    Ok(()) => toast("Saved password removed."),
                    Err(e) => toast(&e.to_string()),
                },
                "quit" => return false,
                _ => {}
            },
            UiMessage::Service(FromService::Available) => {
                self.service_up = true;
                self.service_warned = false;
            }
            UiMessage::Service(FromService::Unavailable) => {
                self.service_up = false;
                if !self.service_warned {
                    self.service_warned = true;
                    toast("The stayline service is not running.");
                }
            }
            UiMessage::Service(FromService::Event(Event::Status(state))) => {
                self.on_state(state);
            }
            UiMessage::Service(FromService::Event(Event::Rejected { reason })) => {
                toast(&format!("Could not connect: {reason}"));
            }
        }
        self.refresh();
        true
    }

    fn on_state(&mut self, state: TunnelState) {
        if let TunnelState::NeedsUser { reason } = &state
            && self.last_alert.as_ref() != Some(reason)
        {
            toast(&format!("VPN needs attention: {reason}"));
            self.last_alert = Some(reason.clone());
        }
        if matches!(state, TunnelState::Connected { .. }) {
            self.last_alert = None;
        }

        let first = !self.auto_connect_checked;
        self.auto_connect_checked = true;
        self.state = state;
        if first && self.state == TunnelState::Disconnected {
            let settings = Settings::load().unwrap_or_default();
            if settings.auto_connect && settings.is_complete() && secret::is_saved() {
                tracing::info!("auto-connecting");
                self.connect();
            }
        }
    }

    fn connect(&mut self) {
        let settings = match Settings::load() {
            Ok(s) if s.is_complete() => s,
            Ok(_) => {
                toast("Set the gateway and username first.");
                open_settings();
                return;
            }
            Err(e) => {
                toast(&e.to_string());
                return;
            }
        };
        match secret::load() {
            Ok(Some(password)) => self.send(Request::Connect {
                profile: settings.profile(),
                password,
            }),
            Ok(None) => toast("No saved password yet. Save one with: stayline-probe save-login"),
            Err(e) => toast(&e.to_string()),
        }
    }

    fn send(&self, request: Request) {
        if let Some(requests) = &self.requests {
            let _ = requests.send(request);
        }
    }

    fn refresh(&self) {
        let (light, text) = if !self.service_up {
            (Light::Alert, "Service not running".to_owned())
        } else {
            describe(&self.state)
        };
        let _ = self.tray.set_icon(Some(icons::icon(light)));
        let tooltip: String = format!("stayline: {text}").chars().take(120).collect();
        let _ = self.tray.set_tooltip(Some(tooltip));
        self.items.status.set_text(format!("stayline: {text}"));

        let idle = matches!(
            self.state,
            TunnelState::Disconnected | TunnelState::NeedsUser { .. }
        );
        self.items.connect.set_enabled(self.service_up && idle);
        self.items
            .disconnect
            .set_enabled(self.service_up && self.state != TunnelState::Disconnected);
        self.items.forget.set_enabled(secret::is_saved());
    }
}

fn describe(state: &TunnelState) -> (Light, String) {
    match state {
        TunnelState::Disconnected => (Light::Off, "Disconnected".into()),
        TunnelState::Connecting { .. } => (Light::Busy, "Connecting…".into()),
        TunnelState::Connected { local_ip } => (Light::On, format!("Connected ({local_ip})")),
        TunnelState::Reconnecting { retry_in_secs, .. } => {
            (Light::Busy, format!("Reconnecting in {retry_in_secs} s"))
        }
        TunnelState::WaitingForNetwork => (Light::Busy, "Waiting for network".into()),
        TunnelState::NeedsUser { reason } => (Light::Alert, format!("Needs attention: {reason}")),
    }
}

fn toast(text: &str) {
    tracing::info!(text, "notification");
    if let Err(e) = Toast::new(Toast::POWERSHELL_APP_ID)
        .title("stayline")
        .text1(text)
        .show()
    {
        tracing::warn!(error = %e, "could not show notification");
    }
}

/// Opens settings.toml in Notepad, creating it with defaults first.
fn open_settings() {
    let path = match settings::path() {
        Ok(path) => path,
        Err(e) => return toast(&e.to_string()),
    };
    if !path.exists()
        && let Err(e) = Settings::default().save()
    {
        return toast(&e.to_string());
    }
    if let Err(e) = std::process::Command::new("notepad.exe").arg(&path).spawn() {
        toast(&format!("Could not open {}: {e}", path.display()));
    }
}

/// `false` if another tray instance is already running in this session.
fn single_instance() -> bool {
    // SAFETY: plain Win32 call; the handle is intentionally kept open for
    // the life of the process.
    unsafe {
        let created = CreateMutexW(None, true, w!("Local\\stayline-tray"));
        created.is_ok() && GetLastError() != ERROR_ALREADY_EXISTS
    }
}

fn init_logging() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let dirs = directories::ProjectDirs::from("", "", "stayline")?;
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("stayline-tray")
        .filename_suffix("log")
        .max_log_files(7)
        .build(dirs.data_local_dir().join("logs"))
        .ok()?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_ansi(false)
        .with_writer(writer)
        .init();
    Some(guard)
}
