//! The GTK4 window: a thin renderer for [`Model`] and a thin sender of [`CoreCommand`]s.
//!
//! There is deliberately nothing clever here. Every label, switch position and refusal comes from
//! the model, the model comes from core, and every action is a command core validates again.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::Duration;

use gtk::prelude::*;
use gtk::{
    Application, ApplicationWindow, Box as GtkBox, Button, CheckButton, FileDialog, HeaderBar,
    Label, ListBox, ListBoxRow, Orientation, ScrolledWindow, Separator, Switch, Window,
};
use gtk4 as gtk;

use crate::client::{CoreCommand, CoreHandle};
use crate::model::{self, CoreUpdate, LinkState, Model, NetworkChoice, ScopeChoice, Severity};

const CSS: &str = "
.banner { padding: 12px; border-radius: 8px; font-weight: bold; }
.banner-neutral { background: #e0e0e0; color: #202020; }
.banner-pending { background: #ffe082; color: #202020; }
.banner-good { background: #2e7d32; color: #ffffff; }
.banner-warning { background: #ef6c00; color: #ffffff; }
.banner-bad { background: #b71c1c; color: #ffffff; }
.reasons { color: #404040; }
.notice { background: #fff8e1; padding: 8px; border-radius: 6px; }
.diagnostics { font-family: monospace; }
";

/// Run the GUI against a core socket.
pub fn run(socket: std::path::PathBuf) -> gtk::glib::ExitCode {
    let app = Application::builder()
        .application_id("org.ghostnector.Gui")
        .build();
    app.connect_activate(move |app| {
        let ui = Rc::new(Ui::new(socket.clone()));
        ui.present(app);
    });
    app.run_with_args::<String>(&[])
}

struct Widgets {
    window: ApplicationWindow,
    banner: Label,
    reasons: Label,
    protection: Switch,
    tor: CheckButton,
    i2p: CheckButton,
    system: CheckButton,
    apps: CheckButton,
    lan: CheckButton,
    lan_reason: Label,
    scope_reason: Label,
    add: Button,
    app_list: ListBox,
    apps_hint: Label,
    notice: Label,
    notice_box: GtkBox,
    connection: Label,
}

struct Ui {
    socket: std::path::PathBuf,
    model: Rc<RefCell<Model>>,
    handle: CoreHandle,
    widgets: RefCell<Option<Rc<Widgets>>>,
    diagnostics: RefCell<Option<Window>>,
    pending_path: RefCell<Option<String>>,
    shown_apps: RefCell<Vec<(u32, String, bool)>>,
}

impl Ui {
    fn new(socket: std::path::PathBuf) -> Self {
        Self {
            socket: socket.clone(),
            model: Rc::new(RefCell::new(Model::default())),
            handle: crate::client::spawn(socket),
            widgets: RefCell::new(None),
            diagnostics: RefCell::new(None),
            pending_path: RefCell::new(None),
            shown_apps: RefCell::new(Vec::new()),
        }
    }

    fn present(self: &Rc<Self>, app: &Application) {
        if let Some(widgets) = self.widgets.borrow().as_ref() {
            widgets.window.present();
            return;
        }

        install_css();
        let widgets = Rc::new(self.build_window(app));
        *self.widgets.borrow_mut() = Some(Rc::clone(&widgets));

        let ui = Rc::clone(self);
        gtk::glib::timeout_add_local(Duration::from_millis(50), move || {
            ui.pump();
            gtk::glib::ControlFlow::Continue
        });

        self.render();
        widgets.window.present();
    }

    fn build_window(self: &Rc<Self>, app: &Application) -> Widgets {
        let window = ApplicationWindow::builder()
            .application(app)
            .title("Ghostnector")
            .default_width(460)
            .default_height(640)
            .build();

        let header = HeaderBar::new();
        let diagnostics_button = Button::with_label("Diagnostics");
        {
            let ui = Rc::clone(self);
            diagnostics_button.connect_clicked(move |_| ui.open_diagnostics());
        }
        header.pack_end(&diagnostics_button);

        // Panic lives behind a menu with a confirmation: accessible, never accidental.
        let menu_button = gtk::MenuButton::builder()
            .icon_name("open-menu-symbolic")
            .tooltip_text("More actions")
            .build();
        let menu = gtk::gio::Menu::new();
        menu.append(Some("Deny all traffic now…"), Some("win.panic"));
        menu_button.set_menu_model(Some(&menu));
        let panic_action = gtk::gio::SimpleAction::new("panic", None);
        {
            let ui = Rc::clone(self);
            panic_action.connect_activate(move |_, _| ui.confirm_panic());
        }
        window.add_action(&panic_action);
        header.pack_end(&menu_button);
        window.set_titlebar(Some(&header));

        let root = GtkBox::new(Orientation::Vertical, 12);
        root.set_margin_top(16);
        root.set_margin_bottom(16);
        root.set_margin_start(16);
        root.set_margin_end(16);

        let banner = Label::new(None);
        banner.set_wrap(true);
        banner.set_xalign(0.0);
        banner.add_css_class("banner");
        root.append(&banner);

        let reasons = Label::new(None);
        reasons.set_wrap(true);
        reasons.set_xalign(0.0);
        reasons.add_css_class("reasons");
        root.append(&reasons);

        let notice = Label::new(None);
        notice.set_wrap(true);
        notice.set_xalign(0.0);
        let dismiss = Button::with_label("Dismiss");
        {
            let ui = Rc::clone(self);
            dismiss.connect_clicked(move |_| {
                ui.model.borrow_mut().clear_notice();
                ui.render();
            });
        }
        let notice_box = GtkBox::new(Orientation::Horizontal, 8);
        notice_box.add_css_class("notice");
        notice_box.set_visible(false);
        notice.set_hexpand(true);
        notice_box.append(&notice);
        notice_box.append(&dismiss);
        root.append(&notice_box);

        // Protection.
        let protection_row = GtkBox::new(Orientation::Horizontal, 8);
        let protection_label = Label::new(Some("_Protection"));
        protection_label.set_use_underline(true);
        protection_label.set_xalign(0.0);
        protection_label.set_hexpand(true);
        let protection = Switch::new();
        protection_label.set_mnemonic_widget(Some(&protection));
        protection.update_property(&[gtk::accessible::Property::Label("Protection on or off")]);
        {
            let ui = Rc::clone(self);
            protection.connect_state_set(move |_, desired| {
                ui.on_protection_switch(desired);
                gtk::glib::Propagation::Proceed
            });
        }
        protection_row.append(&protection_label);
        protection_row.append(&protection);
        root.append(&protection_row);

        root.append(&Separator::new(Orientation::Horizontal));

        // Network.
        let network_label = Label::new(Some("_Network"));
        network_label.set_use_underline(true);
        network_label.set_xalign(0.0);
        root.append(&network_label);
        let network_row = GtkBox::new(Orientation::Horizontal, 12);
        let tor = CheckButton::builder().label("Tor").build();
        let i2p = CheckButton::builder().label("I2P").build();
        i2p.set_group(Some(&tor));
        network_row.append(&tor);
        network_row.append(&i2p);
        root.append(&network_row);
        {
            let ui = Rc::clone(self);
            tor.connect_toggled(move |button| {
                if button.is_active() {
                    ui.choose_network(NetworkChoice::Tor);
                }
            });
        }
        {
            let ui = Rc::clone(self);
            i2p.connect_toggled(move |button| {
                if button.is_active() {
                    ui.choose_network(NetworkChoice::I2p);
                }
            });
        }

        // Scope.
        let scope_label = Label::new(Some("_Scope"));
        scope_label.set_use_underline(true);
        scope_label.set_xalign(0.0);
        root.append(&scope_label);
        let scope_row = GtkBox::new(Orientation::Horizontal, 12);
        let system = CheckButton::builder().label("Whole system").build();
        let apps = CheckButton::builder()
            .label("Selected applications")
            .build();
        apps.set_group(Some(&system));
        scope_row.append(&system);
        scope_row.append(&apps);
        root.append(&scope_row);
        let scope_reason = Label::new(None);
        scope_reason.set_wrap(true);
        scope_reason.set_xalign(0.0);
        scope_reason.add_css_class("reasons");
        root.append(&scope_reason);
        {
            let ui = Rc::clone(self);
            system.connect_toggled(move |button| {
                if button.is_active() {
                    ui.choose_scope(ScopeChoice::System);
                }
            });
        }
        {
            let ui = Rc::clone(self);
            apps.connect_toggled(move |button| {
                if button.is_active() {
                    ui.choose_scope(ScopeChoice::Apps);
                }
            });
        }

        // Local network.
        let lan_row = GtkBox::new(Orientation::Horizontal, 8);
        let lan_label = Label::new(Some("Allow access to the _local network"));
        lan_label.set_use_underline(true);
        lan_label.set_xalign(0.0);
        lan_label.set_hexpand(true);
        let lan = CheckButton::new();
        lan_label.set_mnemonic_widget(Some(&lan));
        lan_row.append(&lan_label);
        lan_row.append(&lan);
        root.append(&lan_row);
        let lan_reason = Label::new(None);
        lan_reason.set_wrap(true);
        lan_reason.set_xalign(0.0);
        lan_reason.add_css_class("reasons");
        root.append(&lan_reason);
        {
            let ui = Rc::clone(self);
            lan.connect_toggled(move |button| {
                ui.choose_lan(button.is_active());
            });
        }

        root.append(&Separator::new(Orientation::Horizontal));

        // Protected applications.
        let apps_header = GtkBox::new(Orientation::Horizontal, 8);
        let apps_title = Label::new(Some("Protected applications"));
        apps_title.set_xalign(0.0);
        apps_title.set_hexpand(true);
        let add = Button::with_label("_Add application…");
        add.set_use_underline(true);
        add.set_sensitive(false);
        {
            let ui = Rc::clone(self);
            add.connect_clicked(move |_| ui.choose_application());
        }
        apps_header.append(&apps_title);
        apps_header.append(&add);
        root.append(&apps_header);

        let apps_hint = Label::new(None);
        apps_hint.set_wrap(true);
        apps_hint.set_xalign(0.0);
        apps_hint.add_css_class("reasons");
        root.append(&apps_hint);

        let app_list = ListBox::new();
        app_list.set_selection_mode(gtk::SelectionMode::None);
        let scroller = ScrolledWindow::builder()
            .child(&app_list)
            .min_content_height(90)
            .vexpand(true)
            .build();
        root.append(&scroller);

        let connection = Label::new(None);
        connection.set_wrap(true);
        connection.set_xalign(0.0);
        connection.add_css_class("reasons");
        root.append(&connection);

        window.set_child(Some(&root));

        Widgets {
            window,
            banner,
            reasons,
            protection,
            tor,
            i2p,
            system,
            apps,
            lan,
            lan_reason,
            scope_reason,
            add,
            app_list,
            apps_hint,
            notice,
            notice_box,
            connection,
        }
    }

    // ------------------------------------------------------------------ core updates

    fn pump(self: &Rc<Self>) {
        let mut applied = Vec::new();
        while let Ok(update) = self.handle.updates.try_recv() {
            if let CoreUpdate::AppSession { id, socket } = &update {
                if let Some(path) = self.pending_path.borrow_mut().take() {
                    if let Err(error) = self.launch_session(*id, socket, &path) {
                        self.handle.send(CoreCommand::AppStop(*id)).ok();
                        self.model
                            .borrow_mut()
                            .apply(CoreUpdate::Notice { message: error });
                    }
                }
            }
            applied.push(update);
        }
        if !applied.is_empty() {
            {
                let mut model = self.model.borrow_mut();
                for update in applied {
                    model.apply(update);
                }
            }
            self.render();
        }
    }

    /// Connect to the prepared session and run the chosen command as the user, exactly as the CLI
    /// does. The command reaches only the user's own shell inside the session.
    fn launch_session(&self, id: u32, socket: &str, path: &str) -> Result<(), String> {
        let command = model::launch_command(path)?;
        let stream = UnixStream::connect(socket)
            .map_err(|error| format!("cannot open the protected session: {error}"))?;
        let mut writer = stream
            .try_clone()
            .map_err(|error| format!("cannot use the protected session: {error}"))?;
        writeln!(writer, "{command}").map_err(|error| format!("cannot start it: {error}"))?;
        writer
            .flush()
            .map_err(|error| format!("cannot start it: {error}"))?;

        // Keep the session alive for as long as the application runs; its output is not this
        // window's business, so a thread drains and discards it until the session ends.
        let mut reader = stream;
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
        self.model.borrow_mut().label_app(id, path);
        Ok(())
    }

    // ------------------------------------------------------------------ user actions

    fn on_protection_switch(self: &Rc<Self>, desired: bool) {
        let model = self.model.borrow();
        let on = model.protection_on();
        if desired == on {
            return;
        }
        if !model.can_toggle() {
            self.render();
            return;
        }
        drop(model);
        if on {
            self.handle.send(CoreCommand::Disconnect).ok();
        } else {
            match self.model.borrow().profile() {
                Ok(profile) => {
                    self.handle
                        .send(CoreCommand::Connect(Box::new(profile)))
                        .ok();
                }
                Err(reason) => {
                    self.model
                        .borrow_mut()
                        .apply(CoreUpdate::Notice { message: reason });
                    self.render();
                }
            }
        }
    }

    fn choose_network(self: &Rc<Self>, network: NetworkChoice) {
        self.apply_selection_change(|model| model.set_network(network));
    }

    fn choose_scope(self: &Rc<Self>, scope: ScopeChoice) {
        self.apply_selection_change(|model| {
            let _ = model.set_scope(scope);
        });
    }

    fn choose_lan(self: &Rc<Self>, allow: bool) {
        self.apply_selection_change(|model| {
            if let Err(reason) = model.set_allow_lan(allow) {
                model.apply(CoreUpdate::Notice {
                    message: reason.to_string(),
                });
            }
        });
    }

    /// A selection change re-applies protection when it is on. Changing what protection covers is a
    /// real transition, so the user confirms it; while applying, the controls are frozen.
    fn apply_selection_change(self: &Rc<Self>, change: impl FnOnce(&mut Model)) {
        let (was_on, can_select) = {
            let model = self.model.borrow();
            (model.protection_on(), model.can_select())
        };
        {
            let mut model = self.model.borrow_mut();
            change(&mut model);
        }
        if !can_select {
            self.render();
            return;
        }
        if !was_on {
            self.render();
            return;
        }
        let profile = match self.model.borrow().profile() {
            Ok(profile) => profile,
            Err(reason) => {
                self.model
                    .borrow_mut()
                    .apply(CoreUpdate::Notice { message: reason });
                self.render();
                return;
            }
        };
        let widgets = match self.widgets.borrow().as_ref() {
            Some(widgets) => Rc::clone(widgets),
            None => return,
        };
        self.render();
        let window = widgets.window.clone();
        let ui = Rc::clone(self);
        let dialog = gtk::AlertDialog::builder()
            .modal(true)
            .message("Change what is protected?")
            .detail(
                "This re-applies protection for the new selection. Traffic may pause while the \
                 policy is replaced.",
            )
            .buttons(["Cancel", "Apply"])
            .cancel_button(0)
            .default_button(1)
            .build();
        dialog.choose(Some(&window), gtk::gio::Cancellable::NONE, move |answer| {
            if answer == Ok(1) {
                ui.handle.send(CoreCommand::Connect(Box::new(profile))).ok();
            } else {
                // Put the controls back to what core last reported.
                ui.sync_selection_from_core();
            }
            ui.render();
        });
    }

    fn sync_selection_from_core(self: &Rc<Self>) {
        self.model.borrow_mut().restore_reported_selection();
    }

    fn choose_application(self: &Rc<Self>) {
        let Some(widgets) = self.widgets.borrow().as_ref().map(Rc::clone) else {
            return;
        };
        let dialog = FileDialog::builder()
            .title("Choose an application to protect")
            .modal(true)
            .build();
        let ui = Rc::clone(self);
        dialog.open(
            Some(&widgets.window),
            gtk::gio::Cancellable::NONE,
            move |result| {
                let Ok(file) = result else { return };
                let Some(path) = file.path() else {
                    return;
                };
                let path = path.to_string_lossy().into_owned();
                if !is_executable(&path) {
                    ui.model.borrow_mut().apply(CoreUpdate::Notice {
                        message: format!("'{path}' is not an executable file."),
                    });
                    ui.render();
                    return;
                }
                *ui.pending_path.borrow_mut() = Some(path);
                if ui.handle.send(CoreCommand::AppRun).is_err() {
                    ui.model.borrow_mut().apply(CoreUpdate::Notice {
                        message: "The Ghostnector client has stopped.".to_string(),
                    });
                    ui.render();
                }
            },
        );
    }

    fn stop_application(self: &Rc<Self>, id: u32) {
        self.handle.send(CoreCommand::AppStop(id)).ok();
    }

    fn confirm_panic(self: &Rc<Self>) {
        let Some(widgets) = self.widgets.borrow().as_ref().map(Rc::clone) else {
            return;
        };
        let ui = Rc::clone(self);
        let dialog = gtk::AlertDialog::builder()
            .modal(true)
            .message("Deny all traffic now?")
            .detail(
                "Ghostnector will apply its fail-closed baseline immediately. All traffic will be \
                 blocked until you turn protection off.",
            )
            .buttons(["Cancel", "Deny everything"])
            .cancel_button(0)
            .default_button(0)
            .build();
        dialog.choose(
            Some(&widgets.window),
            gtk::gio::Cancellable::NONE,
            move |answer| {
                if answer == Ok(1) {
                    ui.handle.send(CoreCommand::Panic).ok();
                }
            },
        );
    }

    // ------------------------------------------------------------------ rendering

    fn render(self: &Rc<Self>) {
        let Some(widgets) = self.widgets.borrow().as_ref().map(Rc::clone) else {
            return;
        };
        let (banner, reasons, link, notice, connected) = {
            let model = self.model.borrow();
            let banner = model.banner();
            let reasons: Vec<String> = model
                .reasons()
                .iter()
                .map(|reason| format!("• {}", reason.as_str()))
                .collect();
            (
                banner,
                reasons.join("\n"),
                model.link().clone(),
                model.notice().map(str::to_string),
                model.current().is_some(),
            )
        };

        for class in [
            "banner-neutral",
            "banner-pending",
            "banner-good",
            "banner-warning",
            "banner-bad",
        ] {
            widgets.banner.remove_css_class(class);
        }
        widgets.banner.add_css_class(match banner.severity {
            Severity::Neutral => "banner-neutral",
            Severity::Pending => "banner-pending",
            Severity::Good => "banner-good",
            Severity::Warning => "banner-warning",
            Severity::Bad => "banner-bad",
        });
        widgets.banner.set_label(&banner.text);
        widgets.reasons.set_label(&reasons);
        widgets.reasons.set_visible(!reasons.is_empty());

        widgets.notice.set_label(notice.as_deref().unwrap_or(""));
        widgets.notice_box.set_visible(notice.is_some());

        match &link {
            LinkState::Connecting => widgets
                .connection
                .set_label("Connecting to the Ghostnector service…"),
            LinkState::Connected { daemon_version } => widgets.connection.set_label(&format!(
                "Connected to the Ghostnector service (core {daemon_version})."
            )),
            LinkState::Disconnected { reason } => widgets.connection.set_label(&format!(
                "Not connected: {reason}\nThe state above is unknown, not a claim."
            )),
        }

        // Controls follow the model and the core's snapshot, never local optimism.
        let (selection, protection_on, can_toggle, can_select, can_launch) = {
            let model = self.model.borrow();
            (
                model.selection(),
                model.protection_on(),
                model.can_toggle(),
                model.can_select(),
                model.can_launch_apps(),
            )
        };
        if widgets.protection.is_active() != protection_on {
            widgets.protection.set_active(protection_on);
        }
        widgets.protection.set_sensitive(can_toggle);
        widgets
            .tor
            .set_active(selection.network == NetworkChoice::Tor);
        widgets
            .i2p
            .set_active(selection.network == NetworkChoice::I2p);
        widgets
            .system
            .set_active(selection.scope == ScopeChoice::System);
        widgets
            .apps
            .set_active(selection.scope == ScopeChoice::Apps);
        if widgets.lan.is_active() != selection.allow_lan {
            widgets.lan.set_active(selection.allow_lan);
        }
        let scope_reason = model::scope_refusal(selection.network, selection.scope).unwrap_or("");
        widgets.scope_reason.set_label(scope_reason);
        widgets.scope_reason.set_visible(!scope_reason.is_empty());
        widgets.apps.set_sensitive(
            can_select && model::scope_refusal(selection.network, ScopeChoice::Apps).is_none(),
        );
        let lan_reason = model::lan_refusal(selection.network, selection.scope).unwrap_or("");
        widgets.lan_reason.set_label(lan_reason);
        widgets.lan_reason.set_visible(!lan_reason.is_empty());
        widgets.lan.set_sensitive(
            can_select && model::lan_refusal(selection.network, selection.scope).is_none(),
        );
        widgets.tor.set_sensitive(can_select);
        widgets.i2p.set_sensitive(can_select);
        widgets.system.set_sensitive(can_select);

        widgets.add.set_sensitive(can_launch);
        widgets.apps_hint.set_label(if can_launch {
            "Applications launched here reach the network only through Ghostnector."
        } else if connected {
            "Turn protection on with the selected-applications scope to add one."
        } else {
            "The list below reflects the last known state only."
        });

        self.render_apps(&widgets);
    }

    fn render_apps(self: &Rc<Self>, widgets: &Rc<Widgets>) {
        let rows = self.model.borrow().app_rows();
        let key: Vec<(u32, String, bool)> = rows
            .iter()
            .map(|row| (row.id, row.label.clone(), row.present))
            .collect();
        if *self.shown_apps.borrow() == key {
            return;
        }
        while let Some(child) = widgets.app_list.first_child() {
            widgets.app_list.remove(&child);
        }
        for row in &rows {
            let list_row = ListBoxRow::new();
            let line = GtkBox::new(Orientation::Horizontal, 8);
            let label = Label::new(Some(&row.label));
            label.set_xalign(0.0);
            label.set_hexpand(true);
            let status = Label::new(Some(if row.present {
                "running"
            } else {
                "not present"
            }));
            status.add_css_class("reasons");
            let stop = Button::with_label("Stop");
            {
                let ui = Rc::clone(self);
                let id = row.id;
                stop.connect_clicked(move |_| ui.stop_application(id));
            }
            line.append(&label);
            line.append(&status);
            line.append(&stop);
            list_row.set_child(Some(&line));
            widgets.app_list.append(&list_row);
        }
        *self.shown_apps.borrow_mut() = key;
    }

    // ------------------------------------------------------------------ diagnostics

    fn open_diagnostics(self: &Rc<Self>) {
        if let Some(window) = self.diagnostics.borrow().as_ref() {
            window.present();
            return;
        }
        let text = self.diagnostics_text();
        let window = Window::builder()
            .title("Ghostnector diagnostics")
            .default_width(560)
            .default_height(520)
            .build();
        let root = GtkBox::new(Orientation::Vertical, 8);
        root.set_margin_top(12);
        root.set_margin_bottom(12);
        root.set_margin_start(12);
        root.set_margin_end(12);
        let view = Label::new(Some(&text));
        view.set_xalign(0.0);
        view.set_yalign(0.0);
        view.set_selectable(true);
        view.set_wrap(true);
        view.add_css_class("diagnostics");
        let scroller = ScrolledWindow::builder()
            .child(&view)
            .vexpand(true)
            .hexpand(true)
            .build();
        root.append(&scroller);
        let copy = Button::with_label("Copy details");
        {
            let view = view.clone();
            copy.connect_clicked(move |_| {
                if let Some(display) = gtk::gdk::Display::default() {
                    display.clipboard().set_text(&view.text());
                }
            });
        }
        root.append(&copy);
        window.set_child(Some(&root));
        let ui = Rc::clone(self);
        window.connect_close_request(move |_| {
            *ui.diagnostics.borrow_mut() = None;
            gtk::glib::Propagation::Proceed
        });
        *self.diagnostics.borrow_mut() = Some(window.clone());
        window.present();
    }

    fn diagnostics_text(&self) -> String {
        let model = self.model.borrow();
        let mut out = String::new();
        let connected = model.current().is_some();
        let snapshot = model.last_known();
        out.push_str(if connected {
            "Live snapshot\n=============\n"
        } else {
            "Last known snapshot (the service is not reachable)\n\
             =================================================\n"
        });
        match snapshot {
            Some(snapshot) => {
                out.push_str(&format!("state: {}\n", gtk_state(&model)));
                if let Some(profile) = &snapshot.profile {
                    out.push_str(&format!(
                        "profile: {} ({})\n",
                        ghostnector_spec::display::scope_line(profile.scope),
                        ghostnector_spec::display::network_line(profile)
                    ));
                    if profile.allow_lan {
                        out.push_str("         including the local network\n");
                    }
                }
                out.push_str(&format!(
                    "policy applied: {}\n",
                    snapshot.health.policy_applied
                ));
                out.push_str(&format!(
                    "verification: {}\n",
                    ghostnector_spec::display::verification_line(snapshot.health.verification)
                ));
                match snapshot.verified_ago_secs {
                    Some(seconds) => out.push_str(&format!("verified: {seconds} s ago\n")),
                    None => out.push_str("verified: never\n"),
                }
                out.push_str(&format!(
                    "services: tor={:?} dns={:?} i2p={:?}\n",
                    snapshot.health.tor, snapshot.health.dns, snapshot.health.i2p
                ));
                out.push_str(&format!(
                    "blocked egress attempts since connect: {}\n",
                    snapshot.blocked_egress_attempts
                ));
                if !snapshot.warnings.is_empty() {
                    out.push_str("warnings:\n");
                    for warning in &snapshot.warnings {
                        out.push_str(&format!("  - {}\n", model::warning_line(*warning)));
                    }
                }
                if !snapshot.reasons.is_empty() {
                    out.push_str("reasons:\n");
                    for reason in &snapshot.reasons {
                        out.push_str(&format!("  - {}\n", reason.as_str()));
                    }
                }
                if !snapshot.exemptions.is_empty() {
                    out.push_str("exemptions (every hole in the policy):\n");
                    for exemption in &snapshot.exemptions {
                        out.push_str(&format!(
                            "  - {:<28} {}\n",
                            exemption.subject, exemption.reason
                        ));
                    }
                }
            }
            None => out.push_str("nothing has been seen yet\n"),
        }
        out.push_str("\nVersions\n========\n");
        out.push_str(&format!(
            "gui: {} ({})\n",
            env!("CARGO_PKG_VERSION"),
            self.socket.display()
        ));
        out.push_str(&format!(
            "core: {}\n",
            model.daemon_version().unwrap_or("not connected")
        ));
        out.push_str(&format!(
            "protocol: {}\n",
            ghostnector_spec::ipc::PROTOCOL_VERSION
        ));
        out
    }
}

fn gtk_state(model: &Model) -> String {
    match model.last_known() {
        Some(snapshot) => match &model.link() {
            LinkState::Connected { .. } => ghostnector_spec::display::state_line(snapshot),
            _ => format!(
                "{} (last known; the service is not reachable)",
                ghostnector_spec::display::state_line(snapshot)
            ),
        },
        None => "unknown".to_string(),
    }
}

fn is_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn install_css() {
    let provider = gtk::CssProvider::new();
    provider.load_from_string(CSS);
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }
}
