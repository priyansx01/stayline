//! The tray app: tray icon, main window and the link to the service.
//!
//! Everything runs on Slint's event loop on the main thread. Other threads
//! (service client, tray and menu events, a second launch) hand work over
//! with `slint::invoke_from_event_loop`. The window is created when opened
//! and dropped when closed, so an idle tray uses little memory.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use slint::{
    ComponentHandle, ModelRc, SharedString, StandardListViewItem, Timer, TimerMode, VecModel,
};
use stayline_config::{Config, Connection, ConnectionEdit, ThemePreference, secret};
use stayline_ipc::{Attention, CertificateReport, Event, Request, TunnelState};
use tauri_winrt_notification::Toast;
use tokio::sync::mpsc;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use zeroize::Zeroizing;

use crate::client::{self, FromService};
use crate::icons::{self, Light};
use crate::{format, instance, theme};

slint::include_modules!();

const TAB_STATUS: i32 = 0;
const TAB_CONNECTIONS: i32 = 1;
const SERVICE_WARNING_DELAY: Duration = Duration::from_secs(5);
const NEW_CONNECTION_NAME: &str = "New connection";
/// Passed by the sign-in entry the installer creates: start quietly in the
/// tray instead of opening the window.
const BACKGROUND_ARG: &str = "--background";
/// App ID of the Start-menu shortcut the installer creates; notifications
/// shown under it say "stayline".
const APP_ID: &str = "Stayline.App";

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

/// Runs `f` on the app. If the app is busy (a callback fired while it was
/// already borrowed), `f` runs right after instead.
fn with_app(f: impl FnOnce(&mut App) + 'static) {
    APP.with(|cell| match cell.try_borrow_mut() {
        Ok(mut app) => {
            if let Some(app) = app.as_mut() {
                f(app);
            }
        }
        Err(_) => Timer::single_shot(Duration::ZERO, move || with_app(f)),
    });
}

/// Same as [`with_app`], from any thread.
fn post(f: impl FnOnce(&mut App) + Send + 'static) {
    if let Err(e) = slint::invoke_from_event_loop(move || with_app(f)) {
        tracing::warn!(error = %e, "event loop gone");
    }
}

pub fn main() {
    let _log = init_logging();
    let background = std::env::args().any(|a| a == BACKGROUND_ARG);
    if background && !load_config().user.start_at_login {
        // The user turned off starting at sign-in.
        return;
    }
    if installed() {
        // SAFETY: plain Win32 call with a static string.
        let _ = unsafe {
            windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID(windows::core::w!(
                "Stayline.App"
            ))
        };
    }

    let Some(show_requests) = instance::claim() else {
        // Already running: the other instance opens its window.
        return;
    };

    if let Err(e) = slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("software".into())
        .select()
    {
        tracing::error!(error = %e, "could not start the UI");
        return;
    }

    let app = match App::new() {
        Ok(app) => app,
        Err(e) => {
            tracing::error!(error = %e, "could not create the tray icon");
            return;
        }
    };
    APP.with(|cell| *cell.borrow_mut() = Some(app));

    MenuEvent::set_event_handler(Some(|event: MenuEvent| {
        let id = event.id.0.clone();
        post(move |app| app.on_menu(&id));
    }));
    TrayIconEvent::set_event_handler(Some(|event: TrayIconEvent| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = event
        {
            post(|app| app.show_window(None));
        }
    }));
    let requests = client::start(|message| post(move |app| app.on_service(message)));
    instance::on_show_request(show_requests, || post(|app| app.show_window(None)));

    with_app(move |app| {
        app.requests = Some(requests);
        if !background {
            let ready = load_config().active().is_some_and(|c| c.is_complete());
            app.show_window((!ready).then_some(TAB_CONNECTIONS));
        }
    });

    if let Err(e) = slint::run_event_loop_until_quit() {
        tracing::error!(error = %e, "event loop failed");
    }
    APP.with(|cell| cell.borrow_mut().take());
}

fn load_config() -> Config {
    Config::load().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "could not load settings");
        Config::default()
    })
}

/// A certificate decision shown on the Status page.
#[derive(Debug, Clone)]
struct TrustPrompt {
    connection: String,
    gateway: String,
    fingerprint: String,
    /// The certificate changed from a pinned one: no way to continue.
    changed: bool,
}

/// Menu items whose text or enabled state changes.
struct Items {
    status: MenuItem,
    connect: MenuItem,
    disconnect: MenuItem,
}

struct App {
    tray: TrayIcon,
    items: Items,
    requests: Option<mpsc::UnboundedSender<Request>>,
    state: TunnelState,
    service_up: bool,
    stats: (u64, u64),
    /// Auto-connect is tried once per launch, on the first status received.
    auto_connect_checked: bool,
    /// The user asked to be connected (and has not disconnected since).
    wants_connected: bool,
    /// Set when the pipe to the service (re)opens; the next status tells
    /// whether a restarted service lost the tunnel.
    resync_on_status: bool,
    service_warned: bool,
    last_alert: Option<String>,
    /// Connection of the last connect request.
    connecting: Option<String>,
    /// Passwords typed with "Save password" off; kept for this session.
    session_passwords: HashMap<String, Zeroizing<String>>,
    trust: Option<TrustPrompt>,
    window: Option<AppWindow>,
    /// Connection shown in the form: `Some(name)`, or `None` for a new one.
    editing: Option<String>,
    clock: Timer,
    cert_checking: bool,
    cert: Option<CertificateReport>,
}

impl App {
    fn new() -> anyhow::Result<Self> {
        let items = Items {
            status: MenuItem::with_id("status", "stayline: starting", false, None),
            connect: MenuItem::with_id("connect", "Connect", false, None),
            disconnect: MenuItem::with_id("disconnect", "Disconnect", false, None),
        };
        let menu = Menu::new();
        menu.append_items(&[
            &MenuItem::with_id("open", "Open stayline", true, None),
            &PredefinedMenuItem::separator(),
            &items.status,
            &items.connect,
            &items.disconnect,
            &PredefinedMenuItem::separator(),
            &MenuItem::with_id("quit", "Quit (VPN stays connected)", true, None),
        ])?;
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_icon(icons::tray_icon(Light::Off))
            .with_tooltip("stayline")
            .build()?;
        Ok(Self {
            tray,
            items,
            requests: None,
            state: TunnelState::Disconnected,
            service_up: false,
            stats: (0, 0),
            auto_connect_checked: false,
            wants_connected: false,
            resync_on_status: false,
            service_warned: false,
            last_alert: None,
            connecting: None,
            session_passwords: HashMap::new(),
            trust: None,
            window: None,
            editing: None,
            clock: Timer::default(),
            cert_checking: false,
            cert: None,
        })
    }

    // ---- events -------------------------------------------------------

    fn on_menu(&mut self, id: &str) {
        match id {
            "open" => self.show_window(None),
            "connect" => self.connect(),
            "disconnect" => self.disconnect(),
            "quit" => {
                self.window = None;
                let _ = slint::quit_event_loop();
            }
            _ => {}
        }
    }

    fn on_service(&mut self, message: FromService) {
        match message {
            FromService::Available => {
                self.service_up = true;
                self.resync_on_status = true;
            }
            FromService::Unavailable => {
                self.service_up = false;
                self.cert_checking = false;
                // Only warn if it stays unreachable, so a service restart
                // does not produce a notification.
                if !self.service_warned {
                    Timer::single_shot(SERVICE_WARNING_DELAY, || {
                        with_app(|app| {
                            if !app.service_up && !app.service_warned {
                                app.service_warned = true;
                                toast(
                                    "The stayline service is not running. Reinstall stayline or ask IT.",
                                );
                            }
                        })
                    });
                }
            }
            FromService::Event(Event::Status(state)) => {
                self.service_warned = false;
                self.on_state(state);
            }
            FromService::Event(Event::Stats { sent, received }) => self.stats = (sent, received),
            FromService::Event(Event::Rejected { reason }) => {
                self.show_window(Some(TAB_CONNECTIONS));
                self.set_form_message(&reason, true);
            }
            FromService::Event(Event::Certificate(report)) => self.on_certificate(report),
        }
        self.refresh();
    }

    fn on_state(&mut self, state: TunnelState) {
        if let TunnelState::NeedsUser { reason, attention } = &state {
            self.wants_connected = false;
            if self.last_alert.as_ref() != Some(reason) {
                self.last_alert = Some(reason.clone());
                self.on_needs_user(reason, attention);
            }
        }
        if matches!(state, TunnelState::Connected { .. }) {
            self.last_alert = None;
            self.trust = None;
        }
        if !matches!(state, TunnelState::Connected { .. }) {
            self.stats = (0, 0);
        }

        let first = !self.auto_connect_checked;
        self.auto_connect_checked = true;
        let after_service_restart = std::mem::take(&mut self.resync_on_status);
        self.state = state;
        if self.state != TunnelState::Disconnected {
            return;
        }
        if first {
            let config = load_config();
            let ready = config
                .active()
                .is_some_and(|c| c.is_complete() && secret::is_saved(&c.name));
            if config.user.auto_connect && ready {
                tracing::info!("auto-connecting");
                self.connect();
            }
        } else if after_service_restart && self.wants_connected {
            // The service restarted (update or crash) and lost the tunnel the
            // user asked for: bring it back.
            tracing::info!("service restarted, reconnecting");
            self.connect();
        }
    }

    fn on_needs_user(&mut self, reason: &str, attention: &Attention) {
        let config = load_config();
        let name = self
            .connecting
            .clone()
            .or_else(|| config.active().map(|c| c.name));
        let connection = name.as_deref().and_then(|n| config.connection(n));

        match attention {
            Attention::CertificateUntrusted {
                fingerprint: Some(fingerprint),
            } if connection
                .as_ref()
                .is_some_and(|c| c.may_trust_on_first_use) =>
            {
                let connection = connection.expect("checked above");
                toast(&format!(
                    "Confirm the certificate of {} to connect.",
                    connection.gateway
                ));
                self.trust = Some(TrustPrompt {
                    connection: connection.name,
                    gateway: connection.gateway,
                    fingerprint: fingerprint.clone(),
                    changed: false,
                });
                self.show_window(Some(TAB_STATUS));
            }
            Attention::CertificateChanged { expected, actual } => {
                toast(
                    "The VPN gateway's certificate has changed. stayline will not connect; contact IT.",
                );
                self.trust = Some(TrustPrompt {
                    connection: name.unwrap_or_default(),
                    gateway: connection.map(|c| c.gateway).unwrap_or_default(),
                    fingerprint: format!("Expected: {expected}\nReceived: {actual}"),
                    changed: true,
                });
                self.show_window(Some(TAB_STATUS));
            }
            _ => {
                toast(&format!("VPN needs your attention: {reason}"));
                self.show_window(Some(TAB_CONNECTIONS));
                if let Some(name) = name {
                    self.edit_connection(Some(&name));
                }
                self.set_form_message(&capitalise(reason), true);
            }
        }
    }

    fn on_certificate(&mut self, report: CertificateReport) {
        self.cert_checking = false;
        let text = match (&report.fingerprint, report.publicly_trusted) {
            (Some(_), true) => "The certificate is publicly trusted; no pin is needed.".to_owned(),
            (Some(fp), false) => {
                let pinned = self
                    .window
                    .as_ref()
                    .and_then(|w| stayline_config::normalize_pin(&w.get_pin()).ok().flatten());
                let reason = plain_certificate_problem(report.problem.as_deref().unwrap_or(""));
                if pinned.as_deref() == Some(fp.as_str()) {
                    format!(
                        "Not publicly trusted ({reason}), but it matches the pinned fingerprint.\nSHA-256: {fp}"
                    )
                } else {
                    format!(
                        "Not publicly trusted ({reason}).\nSHA-256: {fp}\nConfirm this fingerprint with IT before trusting it."
                    )
                }
            }
            (None, _) => report
                .problem
                .clone()
                .unwrap_or_else(|| "Could not check the certificate.".into()),
        };
        if let Some(w) = &self.window {
            w.set_cert_result(text.into());
            w.set_cert_fingerprint(report.fingerprint.clone().unwrap_or_default().into());
            w.set_cert_public(report.publicly_trusted);
        }
        self.cert = Some(report);
    }

    // ---- actions ------------------------------------------------------

    fn connect(&mut self) {
        let config = load_config();
        let Some(connection) = config.active() else {
            self.show_window(Some(TAB_CONNECTIONS));
            self.edit_connection(None);
            self.set_form_message("Add a connection to get started.", true);
            return;
        };
        if !connection.is_complete() {
            self.show_window(Some(TAB_CONNECTIONS));
            self.edit_connection(Some(&connection.name));
            self.set_form_message("Enter your username first.", true);
            return;
        }
        let password = match secret::load(&connection.name) {
            Ok(Some(saved)) => Some(saved),
            Ok(None) => self.session_passwords.get(&connection.name).cloned(),
            Err(e) => {
                tracing::warn!(error = %e, "saved password unreadable");
                self.session_passwords.get(&connection.name).cloned()
            }
        };
        let Some(password) = password else {
            self.show_window(Some(TAB_CONNECTIONS));
            self.edit_connection(Some(&connection.name));
            self.set_form_message("Enter your password, then choose Save and connect.", true);
            return;
        };
        self.last_alert = None;
        self.trust = None;
        self.wants_connected = true;
        self.connecting = Some(connection.name.clone());
        self.send(Request::Connect {
            profile: connection.profile(),
            password,
        });
    }

    fn disconnect(&mut self) {
        self.wants_connected = false;
        self.send(Request::Disconnect);
    }

    fn choose_active(&mut self, index: i32) {
        let mut config = load_config();
        let Some(connection) = config.connections().into_iter().nth(index as usize) else {
            return;
        };
        config.set_active(&connection.name);
        if let Err(e) = config.user.save() {
            toast(&e.to_string());
        }
        self.refresh();
    }

    fn trust_and_connect(&mut self) {
        let Some(prompt) = self.trust.take().filter(|p| !p.changed) else {
            return;
        };
        let mut config = load_config();
        let saved = config
            .trust(&prompt.connection, &prompt.fingerprint)
            .and_then(|()| config.user.save().map_err(|e| e.to_string()));
        match saved {
            Ok(()) => {
                tracing::info!(
                    connection = prompt.connection,
                    "certificate trusted on first use"
                );
                self.connect();
            }
            Err(e) => toast(&e),
        }
        self.refresh();
    }

    /// Loads a connection into the form (`None` starts a new one).
    fn edit_connection(&mut self, name: Option<&str>) {
        let config = load_config();
        let connection = name.and_then(|n| config.connection(n));
        self.editing = connection.as_ref().map(|c| c.name.clone());
        self.cert = None;
        self.cert_checking = false;
        let Some(w) = &self.window else { return };

        let c = connection.unwrap_or(Connection {
            name: NEW_CONNECTION_NAME.into(),
            gateway: String::new(),
            username: String::new(),
            realm: None,
            pin: None,
            managed: false,
            may_trust_on_first_use: true,
        });
        let realm_locked = c.managed
            && config
                .managed
                .connections
                .iter()
                .any(|m| m.name == c.name && m.realm.is_some());
        w.set_conn_name(c.name.clone().into());
        w.set_gateway(c.gateway.clone().into());
        w.set_username(c.username.clone().into());
        w.set_realm(c.realm.clone().unwrap_or_default().into());
        w.set_pin(c.pin.clone().unwrap_or_default().into());
        w.set_password("".into());
        let saved = self.editing.as_deref().is_some_and(secret::is_saved);
        w.set_password_saved(saved);
        w.set_save_password(saved || !self.session_passwords.contains_key(&c.name));
        w.set_conn_managed(c.managed);
        w.set_realm_locked(realm_locked);
        w.set_can_remove(self.editing.is_some() && !c.managed);
        w.set_cert_result("".into());
        w.set_cert_fingerprint("".into());
        w.set_form_error("".into());
        w.set_form_info("".into());
        let index = config
            .connections()
            .iter()
            .position(|x| Some(&x.name) == self.editing.as_ref())
            .map_or(-1, |i| i as i32);
        w.set_selected_index(index);
        w.set_confirm_delete_open(false);
    }

    /// Saves the form. Returns the connection's name, or `None` if invalid.
    fn save_form(&mut self) -> Option<String> {
        let w = self.window.as_ref()?;
        let mut config = load_config();
        let original = self.editing.clone();
        let managed = original.as_deref().is_some_and(|n| config.is_managed(n));

        let (gateway, pin) = if managed {
            if w.get_username().trim().is_empty() {
                self.set_form_message("Enter your username.", true);
                return None;
            }
            (String::new(), None)
        } else {
            match stayline_config::validate(&w.get_gateway(), &w.get_username(), &w.get_pin()) {
                Ok(valid) => valid,
                Err(message) => {
                    self.set_form_message(&message, true);
                    return None;
                }
            }
        };
        let edit = ConnectionEdit {
            name: w.get_conn_name().trim().to_owned(),
            gateway,
            username: w.get_username().trim().to_owned(),
            realm: Some(w.get_realm().trim().to_owned()).filter(|r| !r.is_empty()),
            pin,
        };
        if let Err(message) = config.save_connection(original.as_deref(), edit.clone()) {
            self.set_form_message(&message, true);
            return None;
        }
        let name = if managed {
            original.clone().unwrap_or_default()
        } else {
            edit.name
        };
        if config.user.active.is_none() {
            config.set_active(&name);
        }
        if let Err(e) = config.user.save() {
            self.set_form_message(&e.to_string(), true);
            return None;
        }
        if let Some(old) = original.as_deref().filter(|old| *old != name) {
            if let Err(e) = secret::rename(old, &name) {
                tracing::warn!(error = %e, "could not move the saved password");
            }
            if let Some(p) = self.session_passwords.remove(old) {
                self.session_passwords.insert(name.clone(), p);
            }
        }

        let password = Zeroizing::new(w.get_password().to_string());
        let result = if w.get_save_password() {
            if password.is_empty() {
                Ok(())
            } else {
                self.session_passwords.remove(&name);
                secret::save(&name, &password)
            }
        } else {
            if !password.is_empty() {
                self.session_passwords.insert(name.clone(), password);
            }
            secret::forget(&name)
        };
        if let Err(e) = result {
            self.set_form_message(&e.to_string(), true);
            return None;
        }

        self.refresh_lists();
        self.edit_connection(Some(&name));
        self.set_form_message("Saved.", false);
        Some(name)
    }

    fn remove_connection(&mut self) {
        let Some(name) = self.editing.clone() else {
            return;
        };
        let mut config = load_config();
        if let Err(message) = config.remove_connection(&name) {
            self.set_form_message(&message, true);
            return;
        }
        if let Err(e) = config.user.save() {
            self.set_form_message(&e.to_string(), true);
            return;
        }
        let _ = secret::forget(&name);
        self.session_passwords.remove(&name);
        self.refresh_lists();
        let next = config.connections().into_iter().next().map(|c| c.name);
        self.edit_connection(next.as_deref());
        if let Some(w) = &self.window {
            w.set_confirm_delete_open(false);
        }
        self.set_form_message(&format!("\"{name}\" removed."), false);
        self.refresh();
    }

    fn check_certificate(&mut self) {
        let Some(w) = &self.window else { return };
        let gateway = w.get_gateway().trim().to_owned();
        if gateway.is_empty() {
            return;
        }
        if !self.service_up {
            w.set_cert_result("The stayline service is not running.".into());
            return;
        }
        self.cert_checking = true;
        w.set_cert_result("".into());
        w.set_cert_fingerprint("".into());
        self.send(Request::InspectCertificate { gateway });
        self.refresh();
    }

    fn trust_certificate(&mut self) {
        let Some(fp) = self.cert.as_ref().and_then(|c| c.fingerprint.clone()) else {
            return;
        };
        if let Some(w) = &self.window {
            w.set_pin(fp.into());
        }
        self.set_form_message("Certificate pinned. Choose Save to keep it.", false);
    }

    fn preferences_changed(&mut self) {
        let Some(w) = &self.window else { return };
        let mut config = load_config();
        config.user.auto_connect = w.get_auto_connect();
        config.user.start_at_login = w.get_start_at_login();
        if let Err(e) = config.user.save() {
            toast(&e.to_string());
        }
    }

    fn send(&self, request: Request) {
        if let Some(requests) = &self.requests {
            let _ = requests.send(request);
        }
    }

    // ---- window -------------------------------------------------------

    fn show_window(&mut self, tab: Option<i32>) {
        if self.window.is_none() {
            match self.create_window() {
                Ok(w) => self.window = Some(w),
                Err(e) => {
                    tracing::error!(error = %e, "could not open the window");
                    return;
                }
            }
            self.refresh_lists();
            let active = load_config().active().map(|c| c.name);
            self.edit_connection(active.as_deref());
            self.clock
                .start(TimerMode::Repeated, Duration::from_secs(1), || {
                    with_app(|app| app.refresh_window())
                });
        }
        if let Some(w) = &self.window {
            if let Some(tab) = tab {
                w.set_current_tab(tab);
            }
            if let Err(e) = w.show() {
                tracing::error!(error = %e, "could not show the window");
            }
            w.window().set_minimized(false);
        }
        self.refresh();
    }

    fn create_window(&self) -> Result<AppWindow, slint::PlatformError> {
        let w = AppWindow::new()?;
        w.set_version(env!("CARGO_PKG_VERSION").into());
        let config = load_config();
        w.set_auto_connect(config.user.auto_connect);
        w.set_start_at_login(config.user.start_at_login);

        let theme_mode = match config.user.theme {
            ThemePreference::Light => 0,
            ThemePreference::Dark => 1,
            ThemePreference::System => 2,
        };
        w.set_theme_mode(theme_mode);
        w.set_is_dark(theme::resolve_is_dark(config.user.theme));

        w.on_connect(|| with_app(|app| app.connect()));
        w.on_disconnect(|| with_app(|app| app.disconnect()));
        w.on_cancel_connect(|| with_app(|app| app.disconnect()));
        w.on_choose_active(|index| with_app(move |app| app.choose_active(index)));
        w.on_trust_and_connect(|| with_app(|app| app.trust_and_connect()));
        w.on_dismiss_trust(|| {
            with_app(|app| {
                app.trust = None;
                app.refresh();
            })
        });
        w.on_select_connection(|index| {
            with_app(move |app| {
                let name = load_config()
                    .connections()
                    .into_iter()
                    .nth(index as usize)
                    .map(|c| c.name);
                if name.is_some() {
                    app.edit_connection(name.as_deref());
                }
            })
        });
        w.on_add_connection(|| with_app(|app| app.edit_connection(None)));
        w.on_request_delete_connection(|| {
            with_app(|app| {
                if let Some(w) = &app.window {
                    w.set_confirm_delete_open(true);
                }
            })
        });
        w.on_cancel_delete_connection(|| {
            with_app(|app| {
                if let Some(w) = &app.window {
                    w.set_confirm_delete_open(false);
                }
            })
        });
        w.on_remove_connection(|| with_app(|app| app.remove_connection()));
        w.on_save_settings(|| {
            with_app(|app| {
                app.save_form();
            })
        });
        w.on_save_and_connect(|| {
            with_app(|app| {
                let Some(name) = app.save_form() else { return };
                let mut config = load_config();
                config.set_active(&name);
                let _ = config.user.save();
                if let Some(w) = &app.window {
                    w.set_current_tab(TAB_STATUS);
                }
                app.connect();
            })
        });
        w.on_check_certificate(|| with_app(|app| app.check_certificate()));
        w.on_trust_certificate(|| with_app(|app| app.trust_certificate()));
        w.on_preferences_changed(|| with_app(|app| app.preferences_changed()));
        w.on_theme_changed(|mode| {
            with_app(move |app| {
                let preference = match mode {
                    0 => ThemePreference::Light,
                    1 => ThemePreference::Dark,
                    _ => ThemePreference::System,
                };
                let mut config = load_config();
                config.user.theme = preference;
                if let Err(e) = config.user.save() {
                    toast(&e.to_string());
                }
                if let Some(w) = &app.window {
                    w.set_is_dark(theme::resolve_is_dark(preference));
                }
            })
        });
        w.on_open_logs(open_logs);
        w.on_open_notices(open_notices);
        w.on_filter_components(|query| {
            with_app(move |app| {
                if let Some(w) = &app.window {
                    w.set_components(filtered_components(query.as_str()));
                }
            })
        });
        w.set_components(filtered_components(""));
        w.window().on_close_requested(|| {
            // Drop the window once this callback has returned.
            Timer::single_shot(Duration::ZERO, || {
                with_app(|app| {
                    app.window = None;
                    app.clock.stop();
                })
            });
            slint::CloseRequestResponse::HideWindow
        });
        Ok(w)
    }

    fn set_form_message(&self, text: &str, error: bool) {
        if let Some(w) = &self.window {
            w.set_form_error(if error { text.into() } else { "".into() });
            w.set_form_info(if error { "".into() } else { text.into() });
        }
    }

    /// Fills the connection list and picker.
    fn refresh_lists(&self) {
        let Some(w) = &self.window else { return };
        let config = load_config();
        let connections = config.connections();
        let names: Vec<SharedString> = connections.iter().map(|c| c.name.as_str().into()).collect();
        let items: Vec<StandardListViewItem> = connections
            .iter()
            .map(|c| {
                let label = if c.managed {
                    format!("{}  (managed)", c.name)
                } else {
                    c.name.clone()
                };
                StandardListViewItem::from(SharedString::from(label))
            })
            .collect();
        w.set_connection_names(ModelRc::from(Rc::new(VecModel::from(names))));
        w.set_connection_items(ModelRc::from(Rc::new(VecModel::from(items))));
        w.set_can_add(config.allow_user_connections());
    }

    /// Updates the tray and, if open, the window.
    fn refresh(&self) {
        let (light, text) = self.describe();
        let _ = self.tray.set_icon(Some(icons::tray_icon(light)));
        let tooltip: String = format!("stayline: {text}").chars().take(120).collect();
        let _ = self.tray.set_tooltip(Some(tooltip));
        self.items.status.set_text(format!("Status: {text}"));
        let active = load_config().active().map(|c| c.name);
        self.items.connect.set_text(match &active {
            Some(name) => format!("Connect to {name}"),
            None => "Connect".to_owned(),
        });
        self.items.connect.set_enabled(self.can_connect());
        self.items.disconnect.set_enabled(self.can_disconnect());
        self.refresh_window();
    }

    fn refresh_window(&self) {
        let Some(w) = &self.window else { return };
        let config = load_config();
        if config.user.theme == ThemePreference::System {
            let dark = theme::is_windows_dark_theme();
            if w.get_is_dark() != dark {
                w.set_is_dark(dark);
            }
        }
        let active = config.active();
        let (light, title) = self.describe();
        w.set_state_kind(light.kind());
        w.set_state_title(title.into());
        w.set_state_detail(self.detail().into());
        w.set_needs_attention(matches!(self.state, TunnelState::NeedsUser { .. }));
        w.set_can_connect(self.can_connect());
        w.set_can_disconnect(self.can_disconnect());
        w.set_cert_checking(self.cert_checking);
        w.set_gateway_display(
            active
                .as_ref()
                .map(|c| c.gateway.clone())
                .unwrap_or_default()
                .into(),
        );
        let index = active
            .as_ref()
            .and_then(|a| config.connections().iter().position(|c| c.name == a.name))
            .map_or(-1, |i| i as i32);
        if w.get_active_index() != index {
            w.set_active_index(index);
        }
        w.set_service_status(
            if self.service_up {
                "Running"
            } else {
                "Not running"
            }
            .into(),
        );

        match &self.trust {
            Some(prompt) => {
                w.set_trust_mode(if prompt.changed { 2 } else { 1 });
                w.set_trust_gateway(prompt.gateway.clone().into());
                w.set_trust_fingerprint(prompt.fingerprint.clone().into());
            }
            None => w.set_trust_mode(0),
        }

        if let TunnelState::Connected {
            local_ip,
            since_unix,
        } = &self.state
        {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            w.set_tunnel_ip(local_ip.clone().into());
            w.set_connected_for(format::duration(now.saturating_sub(*since_unix)).into());
            w.set_sent(format::bytes(self.stats.0).into());
            w.set_received(format::bytes(self.stats.1).into());
        } else {
            for setter in [
                AppWindow::set_tunnel_ip,
                AppWindow::set_connected_for,
                AppWindow::set_sent,
                AppWindow::set_received,
            ] {
                setter(w, "–".into());
            }
        }
    }

    fn can_connect(&self) -> bool {
        self.service_up
            && matches!(
                self.state,
                TunnelState::Disconnected | TunnelState::NeedsUser { .. }
            )
    }

    fn can_disconnect(&self) -> bool {
        self.service_up
            && !matches!(
                self.state,
                TunnelState::Disconnected | TunnelState::NeedsUser { .. }
            )
    }

    fn describe(&self) -> (Light, String) {
        if !self.service_up {
            return (Light::Alert, "Service not running".into());
        }
        match &self.state {
            TunnelState::Disconnected => (Light::Off, "Disconnected".into()),
            TunnelState::Connecting { .. } => (Light::Busy, "Connecting…".into()),
            TunnelState::Connected { .. } => (Light::On, "Connected".into()),
            TunnelState::Reconnecting { .. } => (Light::Busy, "Reconnecting…".into()),
            TunnelState::WaitingForNetwork => (Light::Busy, "Waiting for network…".into()),
            TunnelState::NeedsUser { .. } => (Light::Alert, "Needs your attention".into()),
        }
    }

    fn detail(&self) -> String {
        if !self.service_up {
            return "The stayline service is not running, so the VPN cannot connect.".into();
        }
        match &self.state {
            TunnelState::Disconnected => "The VPN is off.".into(),
            TunnelState::Connecting { attempt } if *attempt > 1 => format!("Attempt {attempt}"),
            TunnelState::Connecting { .. } => "Logging in to the gateway.".into(),
            TunnelState::Connected { .. } => {
                "Your traffic to the company network goes through the VPN.".into()
            }
            TunnelState::Reconnecting {
                retry_in_secs,
                last_error,
                ..
            } => format!(
                "{last_error}. Trying again in {retry_in_secs} s, or as soon as the network changes."
            ),
            TunnelState::WaitingForNetwork => {
                "No network connection. stayline reconnects as soon as you are back online.".into()
            }
            TunnelState::NeedsUser { reason, .. } => capitalise(reason),
        }
    }
}

/// Turns rustls' certificate error text into something a user can read.
fn plain_certificate_problem(problem: &str) -> &'static str {
    if problem.contains("UnknownIssuer") {
        "self-signed or issued by an unknown authority"
    } else if problem.contains("NotValidForName") || problem.contains("not valid for name") {
        "issued for a different name than this address"
    } else if problem.contains("Expired") {
        "expired"
    } else if problem.contains("NotValidYet") {
        "not valid yet; check the computer's clock"
    } else {
        "not trusted by Windows' public certificate authorities"
    }
}

fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn toast(text: &str) {
    tracing::info!(text, "notification");
    let app_id = if installed() {
        APP_ID
    } else {
        Toast::POWERSHELL_APP_ID
    };
    if let Err(e) = Toast::new(app_id).title("stayline").text1(text).show() {
        tracing::warn!(error = %e, "could not show notification");
    }
}

/// Third-party components shipped with stayline, generated by
/// `scripts\gen-notices.ps1` as `name<TAB>version<TAB>licence` lines.
const THIRD_PARTY: &str = include_str!("../third-party.txt");

fn filtered_components(query: &str) -> ModelRc<Component> {
    let q = query.trim().to_lowercase();
    let rows: Vec<Component> = THIRD_PARTY
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '\t');
            let name = parts.next()?;
            let version = parts.next()?;
            let license = parts.next()?;
            if q.is_empty()
                || name.to_lowercase().contains(&q)
                || version.to_lowercase().contains(&q)
                || license.to_lowercase().contains(&q)
            {
                Some(Component {
                    name: name.into(),
                    version: version.into(),
                    license: license.into(),
                })
            } else {
                None
            }
        })
        .collect();
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

/// Opens the full licence texts: next to the installed app, or in the
/// source tree when running a development build.
fn open_notices() {
    const FILE: &str = "THIRD-PARTY-NOTICES.html";
    let beside_exe = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join(FILE)));
    let in_source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(FILE);
    let Some(path) = beside_exe
        .filter(|p| p.exists())
        .or(Some(in_source).filter(|p| p.exists()))
    else {
        toast("The licence texts are missing from this installation.");
        return;
    };
    if let Err(e) = std::process::Command::new("explorer.exe")
        .arg(&path)
        .spawn()
    {
        toast(&format!("Could not open {}: {e}", path.display()));
    }
}

/// Running from an installed copy (which has the Start-menu shortcut that
/// registers the notification app ID), not from a build folder.
fn installed() -> bool {
    let exe = std::env::current_exe().ok();
    let program_files = std::env::var_os("ProgramFiles").map(std::path::PathBuf::from);
    matches!((exe, program_files), (Some(exe), Some(pf)) if exe.starts_with(&pf))
}

/// Opens the service's log folder (the tray's own logs sit in the user's
/// local app data).
fn open_logs() {
    let dir = std::env::var_os("ProgramData")
        .map(|base| std::path::Path::new(&base).join("stayline").join("logs"))
        .filter(|dir| dir.exists())
        .or_else(|| {
            directories::ProjectDirs::from("", "", "stayline")
                .map(|d| d.data_local_dir().join("logs"))
        });
    if let Some(dir) = dir
        && let Err(e) = std::process::Command::new("explorer.exe").arg(&dir).spawn()
    {
        toast(&format!("Could not open {}: {e}", dir.display()));
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
