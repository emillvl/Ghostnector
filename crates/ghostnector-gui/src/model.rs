//! The whole presentation logic: state to view, controls to intents, refusals to plain words.
//!
//! Nothing here touches the network, the kernel, or a widget. The rules encoded are the ones the
//! interface must not get wrong:
//!
//! * `Protected` is only ever what the core said in its latest `Snapshot` for the current
//!   connection epoch. A toggle, a version string, or a memory of a request is not evidence.
//! * A snapshot from an earlier epoch, or an older generation within the epoch, is discarded.
//! * When the core is unreachable, the state is *unknown*: the last known snapshot is kept for
//!   diagnostics, clearly labelled, and never rendered as current.
//! * Unsupported combinations are refused with a plain sentence here, and core refuses them again.

use std::collections::BTreeMap;

use ghostnector_spec::display;
use ghostnector_spec::ipc::Event;
use ghostnector_spec::{Networks, Profile, ProtectionState, Reason, Scope, Snapshot, Warning};

/// Which overlay the user is asking for. The two are alternatives, never layers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkChoice {
    /// Through Tor.
    Tor,
    /// Through I2P.
    I2p,
}

/// How much of the machine the user is asking to cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeChoice {
    /// Every process on the machine.
    System,
    /// Only applications launched through Ghostnector.
    Apps,
}

/// The user's current selection. It is what the next `Connect` would carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    /// The selected network.
    pub network: NetworkChoice,
    /// The selected scope.
    pub scope: ScopeChoice,
    /// Whether the local network is opted in.
    pub allow_lan: bool,
}

impl Default for Selection {
    fn default() -> Self {
        Self {
            network: NetworkChoice::Tor,
            scope: ScopeChoice::System,
            allow_lan: false,
        }
    }
}

impl Selection {
    /// The selection that a profile in force represents, so the controls follow core.
    pub fn from_profile(profile: &Profile) -> Self {
        Self {
            network: if profile.networks.i2p {
                NetworkChoice::I2p
            } else {
                NetworkChoice::Tor
            },
            scope: if profile.scope == Scope::App {
                ScopeChoice::Apps
            } else {
                ScopeChoice::System
            },
            allow_lan: profile.allow_lan,
        }
    }
}

/// What the connection to the control plane is doing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// Opening, or re-opening, the connections.
    Connecting,
    /// Both connections are up.
    Connected {
        /// The daemon's version, from its handshake.
        daemon_version: String,
    },
    /// Either connection is down; the state is unknown until it is back.
    Disconnected {
        /// Why, in plain words.
        reason: String,
    },
}

/// One update from the core client worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoreUpdate {
    /// A new connection attempt began. Anything from an older epoch is now worthless.
    Connecting {
        /// The new epoch.
        epoch: u64,
    },
    /// The handshake succeeded.
    Connected {
        /// The epoch.
        epoch: u64,
        /// The daemon's version.
        daemon_version: String,
    },
    /// The authoritative snapshot, fetched or pushed.
    Snapshot {
        /// The epoch.
        epoch: u64,
        /// The snapshot.
        snapshot: Box<Snapshot>,
    },
    /// A subscribed event.
    Event {
        /// The epoch.
        epoch: u64,
        /// The event.
        event: Event,
    },
    /// A session was prepared for a protected application.
    AppSession {
        /// The group handle.
        id: u32,
        /// The user-owned session socket.
        socket: String,
    },
    /// A message for the user; not a state claim.
    Notice {
        /// Plain, non-sensitive text.
        message: String,
    },
    /// The connection was lost.
    Disconnected {
        /// The epoch that ended.
        epoch: u64,
        /// Why, in plain words.
        reason: String,
    },
}

/// How loudly a banner speaks. Purely presentational.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// No claim: off, or unknown.
    Neutral,
    /// A transition is in progress.
    Pending,
    /// Verified protection.
    Good,
    /// Applied but not verified, or a warning.
    Warning,
    /// Fail-closed.
    Bad,
}

/// What the status area shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Banner {
    /// The one-line statement, taken from the shared wording.
    pub text: String,
    /// The severity for layout and colour.
    pub severity: Severity,
}

/// One protected application, as the list shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRow {
    /// The handle used to stop it; never displayed.
    pub id: u32,
    /// What the user called it (or a neutral ordinal).
    pub label: String,
    /// Whether the group exists right now.
    pub present: bool,
}

/// Why a selection cannot be used, in plain words.
pub fn scope_refusal(network: NetworkChoice, scope: ScopeChoice) -> Option<&'static str> {
    match (network, scope) {
        (NetworkChoice::I2p, ScopeChoice::Apps) => Some(
            "I2P protects the whole system in this version, so selected applications are not \
             available with it.",
        ),
        _ => None,
    }
}

/// Why the local-network switch cannot be turned on for a selection, in plain words.
pub fn lan_refusal(network: NetworkChoice, scope: ScopeChoice) -> Option<&'static str> {
    match (network, scope) {
        (NetworkChoice::I2p, _) => Some("I2P has no local-network exception."),
        (_, ScopeChoice::Apps) => Some(
            "Per-application protection preserves each application's own address, so local-network \
             access is not available.",
        ),
        _ => None,
    }
}

/// A short, plain description of a warning the profile carries.
pub fn warning_line(warning: Warning) -> &'static str {
    match warning {
        Warning::I2pExposesHostIp => {
            "I2P participants and services can see this machine's IP address; this is inherent to I2P."
        }
        Warning::SystemScopeCoversAllUsers => {
            "Protecting the whole system also covers other logged-in users and system services."
        }
        Warning::LanExceptionWidensExposure => {
            "Allowing the local network widens what protected traffic can reach."
        }
        Warning::AuthenticatedDnsOverTorIsSlower => {
            "Authenticated DNS over Tor adds latency to every uncached lookup."
        }
        Warning::BridgesCostLatency => "Bridges cost latency and are only worth it where Tor is blocked.",
    }
}

/// Quote one path for the user's own shell inside the session. The command never crosses a
/// privileged interface: the kernel already decided who may connect to the session socket, and the
/// shell runs as the user.
pub fn shell_quote(path: &str) -> Result<String, String> {
    if path.is_empty() {
        return Err("choose an application first".to_string());
    }
    if path.contains('\n') || path.contains('\r') {
        return Err("that path contains a line break".to_string());
    }
    Ok(format!("'{}'", path.replace('\'', "'\\''")))
}

/// The command the session shell should run for a chosen application.
pub fn launch_command(path: &str) -> Result<String, String> {
    Ok(format!("exec {}", shell_quote(path)?))
}

/// The display name for a chosen application.
pub fn app_label(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| path.to_string())
}

/// The presentation model. All widget code reads this; all tests drive this.
#[derive(Debug)]
pub struct Model {
    epoch: u64,
    link: LinkState,
    snapshot: Option<Snapshot>,
    generation: u64,
    notice: Option<String>,
    selection: Selection,
    reported: Option<Selection>,
    app_labels: BTreeMap<u32, String>,
    launched: Vec<u32>,
}

impl Default for Model {
    fn default() -> Self {
        Self {
            epoch: 0,
            link: LinkState::Connecting,
            snapshot: None,
            generation: 0,
            notice: None,
            selection: Selection::default(),
            reported: None,
            app_labels: BTreeMap::new(),
            launched: Vec::new(),
        }
    }
}

impl Model {
    /// Apply one update from the core client.
    pub fn apply(&mut self, update: CoreUpdate) {
        match update {
            CoreUpdate::Connecting { epoch } => {
                self.epoch = epoch;
                self.link = LinkState::Connecting;
                // The last known snapshot is kept for diagnostics, but it is not current, and its
                // generation belongs to another connection: the new epoch starts its own ordering.
                self.generation = 0;
                self.notice = None;
            }
            CoreUpdate::Connected {
                epoch,
                daemon_version,
            } => {
                if epoch == self.epoch {
                    self.link = LinkState::Connected { daemon_version };
                }
            }
            CoreUpdate::Snapshot { epoch, snapshot } => self.accept_snapshot(epoch, *snapshot),
            CoreUpdate::Event { epoch, event } => match event {
                Event::StateChanged(snapshot) => self.accept_snapshot(epoch, *snapshot),
                Event::Notice { message } => {
                    if epoch == self.epoch {
                        self.notice = Some(message);
                    }
                }
                Event::Warning(warning) => {
                    if epoch == self.epoch {
                        self.notice = Some(warning_line(warning).to_string());
                    }
                }
                Event::DeniedEgress { .. } => {
                    // The count itself is in the snapshot; nothing to invent.
                }
            },
            CoreUpdate::AppSession { id, socket: _ } => {
                self.launched.push(id);
            }
            CoreUpdate::Notice { message } => {
                self.notice = Some(message);
            }
            CoreUpdate::Disconnected { epoch, reason } => {
                if epoch == self.epoch {
                    self.link = LinkState::Disconnected { reason };
                }
            }
        }
    }

    fn accept_snapshot(&mut self, epoch: u64, snapshot: Snapshot) {
        if epoch != self.epoch {
            // Stale: from a connection that no longer exists.
            return;
        }
        if snapshot.generation < self.generation {
            // Older than what is already shown, within this epoch.
            return;
        }
        // A repeated state updates its reasons without bumping the generation, so equal is accepted.
        self.generation = snapshot.generation;
        if let Some(profile) = &snapshot.profile {
            // Controls follow core: whatever is in force is what the window shows selected.
            let reported = Selection::from_profile(profile);
            self.selection = reported;
            self.reported = Some(reported);
        }
        self.snapshot = Some(snapshot);
    }

    /// Whether both connections are up.
    fn link_is_connected(&self) -> bool {
        matches!(self.link, LinkState::Connected { .. })
    }

    /// The current connection state.
    pub fn link(&self) -> &LinkState {
        &self.link
    }

    /// The daemon version, once handshaken.
    pub fn daemon_version(&self) -> Option<&str> {
        match &self.link {
            LinkState::Connected { daemon_version } => Some(daemon_version),
            _ => None,
        }
    }

    /// The authoritative snapshot, and only while connected to the core that produced it.
    pub fn current(&self) -> Option<&Snapshot> {
        if self.link_is_connected() {
            self.snapshot.as_ref()
        } else {
            None
        }
    }

    /// The last snapshot seen on any connection, for the diagnostics view only.
    pub fn last_known(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// The one-line status, never rosier than the core's own words.
    pub fn banner(&self) -> Banner {
        match (&self.link, &self.snapshot) {
            (LinkState::Connected { .. }, Some(snapshot)) => Banner {
                text: display::state_line(snapshot),
                severity: severity(snapshot.state),
            },
            _ => Banner {
                text: "Protection state unknown — cannot reach the Ghostnector service".to_string(),
                severity: Severity::Neutral,
            },
        }
    }

    /// The reasons core gave for its current state, verbatim.
    pub fn reasons(&self) -> &[Reason] {
        self.current()
            .map(|snapshot| &snapshot.reasons[..])
            .unwrap_or(&[])
    }

    /// The most recent one-off message, if any.
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    /// Clear a message after it has been shown.
    pub fn clear_notice(&mut self) {
        self.notice = None;
    }

    /// The selection the controls show.
    pub fn selection(&self) -> Selection {
        self.selection
    }

    /// Put the controls back to what the core last reported, discarding a change the user did not
    /// confirm.
    pub fn restore_reported_selection(&mut self) {
        if let Some(reported) = self.reported {
            self.selection = reported;
        }
    }

    /// Choose a network. I2P narrows the selection to what it supports, in one step.
    pub fn set_network(&mut self, network: NetworkChoice) {
        self.selection.network = network;
        if network == NetworkChoice::I2p {
            self.selection.scope = ScopeChoice::System;
            self.selection.allow_lan = false;
        }
    }

    /// Choose a scope. An unsupported pair is refused with its reason.
    pub fn set_scope(&mut self, scope: ScopeChoice) -> Result<(), &'static str> {
        if let Some(reason) = scope_refusal(self.selection.network, scope) {
            return Err(reason);
        }
        self.selection.scope = scope;
        if scope == ScopeChoice::Apps {
            self.selection.allow_lan = false;
        }
        Ok(())
    }

    /// Turn the local-network exception on or off; refused for unsupported pairs.
    pub fn set_allow_lan(&mut self, allow: bool) -> Result<(), &'static str> {
        if allow {
            if let Some(reason) = lan_refusal(self.selection.network, self.selection.scope) {
                return Err(reason);
            }
        }
        self.selection.allow_lan = allow;
        Ok(())
    }

    /// Why the current selection cannot be used, if it cannot.
    pub fn selection_refusal(&self) -> Option<&'static str> {
        scope_refusal(self.selection.network, self.selection.scope).or_else(|| {
            self.selection
                .allow_lan
                .then(|| lan_refusal(self.selection.network, self.selection.scope))
                .flatten()
        })
    }

    /// The profile a `Connect` should carry. Core validates it again.
    pub fn profile(&self) -> Result<Profile, String> {
        if let Some(reason) = self.selection_refusal() {
            return Err(reason.to_string());
        }
        let (scope, networks) = match (self.selection.network, self.selection.scope) {
            (NetworkChoice::I2p, _) => (Scope::System, Networks::i2p()),
            (NetworkChoice::Tor, ScopeChoice::Apps) => (Scope::App, Networks::tor()),
            (NetworkChoice::Tor, ScopeChoice::System) => (Scope::System, Networks::tor()),
        };
        Ok(Profile {
            scope,
            networks,
            allow_lan: self.selection.allow_lan,
            ..Profile::default()
        })
    }

    /// Whether the policy in force (or requested) is not off.
    pub fn protection_on(&self) -> bool {
        self.current()
            .map(|snapshot| snapshot.state != ProtectionState::Off)
            .unwrap_or(false)
    }

    /// Whether the protection switch can be used right now.
    pub fn can_toggle(&self) -> bool {
        self.current()
            .map(|snapshot| snapshot.state != ProtectionState::Applying)
            .unwrap_or(false)
    }

    /// Whether network/scope choices can be changed right now. Changing them while protection is
    /// on re-applies protection; the view asks first.
    pub fn can_select(&self) -> bool {
        self.current()
            .map(|snapshot| snapshot.state != ProtectionState::Applying)
            .unwrap_or(false)
    }

    /// Whether a protected application can be launched right now: the active profile must be the
    /// app scope and traffic must be under policy.
    pub fn can_launch_apps(&self) -> bool {
        self.current()
            .map(|snapshot| {
                snapshot.state.is_protected()
                    && snapshot.profile.as_ref().map(|p| p.scope) == Some(Scope::App)
            })
            .unwrap_or(false)
    }

    /// The protected applications as the list shows them. Ids never appear.
    pub fn app_rows(&self) -> Vec<AppRow> {
        let Some(snapshot) = self.current() else {
            return Vec::new();
        };
        snapshot
            .apps
            .iter()
            .enumerate()
            .map(|(index, app)| AppRow {
                id: app.id,
                label: self
                    .app_labels
                    .get(&app.id)
                    .cloned()
                    .unwrap_or_else(|| format!("Protected application {}", index + 1)),
                present: app.present,
            })
            .collect()
    }

    /// Remember the name of an application we launched, so the list can show it.
    pub fn label_app(&mut self, id: u32, path: &str) {
        self.app_labels.insert(id, app_label(path));
    }

    /// The applications this window launched since it started, for cleanup on close.
    pub fn launched(&self) -> &[u32] {
        &self.launched
    }
}

fn severity(state: ProtectionState) -> Severity {
    match state {
        ProtectionState::Off => Severity::Neutral,
        ProtectionState::Applying => Severity::Pending,
        ProtectionState::Protected => Severity::Good,
        ProtectionState::Degraded | ProtectionState::Portal => Severity::Warning,
        ProtectionState::Blocked => Severity::Bad,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghostnector_spec::{Health, Verification};

    fn snapshot(state: ProtectionState, generation: u64) -> Snapshot {
        Snapshot {
            state,
            generation,
            ..Snapshot::default()
        }
    }

    fn app_snapshot(state: ProtectionState, generation: u64) -> Snapshot {
        Snapshot {
            state,
            generation,
            profile: Some(Profile {
                scope: Scope::App,
                networks: Networks::tor(),
                ..Profile::default()
            }),
            apps: vec![ghostnector_spec::AppStatus {
                id: 7,
                address: "10.200.0.2".parse().expect("address"),
                present: true,
            }],
            ..Snapshot::default()
        }
    }

    fn connected(model: &mut Model) {
        model.apply(CoreUpdate::Connecting { epoch: 1 });
        model.apply(CoreUpdate::Connected {
            epoch: 1,
            daemon_version: "0.1.0".to_string(),
        });
    }

    #[test]
    fn a_fresh_connection_shows_unknown_not_the_old_state() {
        let mut model = Model::default();
        connected(&mut model);
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(snapshot(ProtectionState::Protected, 4)),
        });
        assert!(model.banner().text.contains("and verified"));

        // The core restarts. Until its first snapshot arrives, nothing is known.
        model.apply(CoreUpdate::Connecting { epoch: 2 });
        assert!(model.current().is_none());
        let banner = model.banner();
        assert!(banner.text.contains("unknown"), "{}", banner.text);
        assert_eq!(banner.severity, Severity::Neutral);
        assert!(
            model.last_known().is_some(),
            "diagnostics may still say what was seen"
        );
    }

    #[test]
    fn a_snapshot_from_an_old_epoch_is_discarded() {
        let mut model = Model::default();
        connected(&mut model);
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(snapshot(ProtectionState::Protected, 3)),
        });
        model.apply(CoreUpdate::Connecting { epoch: 2 });
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(snapshot(ProtectionState::Off, 99)),
        });
        assert!(
            model.current().is_none(),
            "an old epoch may not repaint the window"
        );
    }

    #[test]
    fn an_older_generation_within_an_epoch_is_discarded() {
        let mut model = Model::default();
        connected(&mut model);
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(snapshot(ProtectionState::Protected, 5)),
        });
        model.apply(CoreUpdate::Event {
            epoch: 1,
            event: Event::StateChanged(Box::new(snapshot(ProtectionState::Off, 4))),
        });
        assert!(model.banner().text.contains("and verified"));
        // A repeated state carries new reasons with the same generation: it must be accepted.
        model.apply(CoreUpdate::Event {
            epoch: 1,
            event: Event::StateChanged(Box::new(Snapshot {
                state: ProtectionState::Protected,
                generation: 5,
                reasons: vec![Reason::new("checked again")],
                ..Snapshot::default()
            })),
        });
        assert_eq!(model.reasons().len(), 1);
    }

    #[test]
    fn a_lost_connection_stops_the_state_claim_but_keeps_the_last_words() {
        let mut model = Model::default();
        connected(&mut model);
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(snapshot(ProtectionState::Protected, 1)),
        });
        model.apply(CoreUpdate::Disconnected {
            epoch: 1,
            reason: "the service closed the connection".to_string(),
        });
        assert!(model.current().is_none());
        assert!(model.banner().text.contains("unknown"));
        assert!(model.last_known().is_some());
        assert!(!model.can_toggle());
        assert!(!model.can_launch_apps());
    }

    #[test]
    fn the_state_words_come_from_the_shared_display_module() {
        let mut model = Model::default();
        connected(&mut model);
        for (state, expected) in [
            (ProtectionState::Off, "off — traffic is not protected"),
            (ProtectionState::Protected, "protected — and verified"),
            (ProtectionState::Degraded, "protected, but unverified"),
            (ProtectionState::Blocked, "blocked — no traffic can leave"),
        ] {
            model.apply(CoreUpdate::Snapshot {
                epoch: 1,
                snapshot: Box::new(snapshot(state, 10)),
            });
            assert_eq!(model.banner().text, expected);
        }
    }

    #[test]
    fn the_toggle_is_on_for_everything_except_off_and_moves_only_when_known() {
        let mut model = Model::default();
        assert!(!model.protection_on());
        assert!(!model.can_toggle(), "unknown is not togglable");
        connected(&mut model);
        for (state, on, togglable) in [
            (ProtectionState::Off, false, true),
            (ProtectionState::Applying, true, false),
            (ProtectionState::Degraded, true, true),
            (ProtectionState::Protected, true, true),
            (ProtectionState::Blocked, true, true),
            (ProtectionState::Portal, true, true),
        ] {
            model.apply(CoreUpdate::Snapshot {
                epoch: 1,
                snapshot: Box::new(snapshot(state, 20)),
            });
            assert_eq!(model.protection_on(), on, "{state:?}");
            assert_eq!(model.can_toggle(), togglable, "{state:?}");
        }
    }

    #[test]
    fn an_unsupported_pair_is_refused_with_a_plain_sentence() {
        let mut model = Model::default();
        model.set_network(NetworkChoice::I2p);
        assert_eq!(model.selection().scope, ScopeChoice::System);
        let reason = model.set_scope(ScopeChoice::Apps).expect_err("must refuse");
        assert!(reason.contains("whole system"), "{reason}");
        assert_eq!(model.selection().scope, ScopeChoice::System);

        model.set_network(NetworkChoice::Tor);
        model.set_scope(ScopeChoice::Apps).expect("supported");
        let reason = model.set_allow_lan(true).expect_err("must refuse");
        assert!(reason.contains("own address"), "{reason}");
        assert!(!model.selection().allow_lan);

        model.set_network(NetworkChoice::I2p);
        let reason = model.set_allow_lan(true).expect_err("must refuse");
        assert!(reason.contains("I2P"), "{reason}");
    }

    #[test]
    fn a_tor_system_selection_becomes_the_expected_profile() {
        let mut model = Model::default();
        model
            .set_allow_lan(true)
            .expect("lan is fine for tor+system");
        let profile = model.profile().expect("profile");
        assert_eq!(profile.scope, Scope::System);
        assert!(profile.networks.tor);
        assert!(profile.allow_lan);

        model.set_scope(ScopeChoice::Apps).expect("supported");
        assert!(!model.selection().allow_lan, "apps drops the LAN exception");
        let profile = model.profile().expect("profile");
        assert_eq!(profile.scope, Scope::App);
        assert!(profile.networks.tor);
    }

    #[test]
    fn the_window_follows_the_profile_core_reports() {
        let mut model = Model::default();
        model.set_network(NetworkChoice::Tor);
        connected(&mut model);
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(Snapshot {
                state: ProtectionState::Degraded,
                generation: 1,
                profile: Some(Profile {
                    scope: Scope::System,
                    networks: Networks::i2p(),
                    allow_lan: false,
                    ..Profile::default()
                }),
                ..Snapshot::default()
            }),
        });
        assert_eq!(model.selection().network, NetworkChoice::I2p);
        assert_eq!(model.selection().scope, ScopeChoice::System);
    }

    #[test]
    fn apps_are_launchable_only_in_a_protected_app_scope() {
        let mut model = Model::default();
        connected(&mut model);
        assert!(!model.can_launch_apps(), "the default is a system scope");
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(app_snapshot(ProtectionState::Degraded, 1)),
        });
        assert!(model.can_launch_apps());
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(app_snapshot(ProtectionState::Blocked, 2)),
        });
        assert!(
            !model.can_launch_apps(),
            "blocked is not a place to start apps"
        );
    }

    #[test]
    fn app_rows_never_show_an_internal_handle() {
        let mut model = Model::default();
        connected(&mut model);
        model.label_app(7, "/usr/bin/firefox");
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(app_snapshot(ProtectionState::Degraded, 1)),
        });
        let rows = model.app_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "firefox");
        assert_eq!(rows[0].id, 7, "the handle is kept, not displayed");
        // An unlabelled group gets an ordinal, not a namespace id.
        let mut fresh = Model::default();
        connected(&mut fresh);
        fresh.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(app_snapshot(ProtectionState::Degraded, 1)),
        });
        assert_eq!(fresh.app_rows()[0].label, "Protected application 1");
        assert!(!fresh.app_rows()[0].label.contains('7'));
    }

    #[test]
    fn notices_are_shown_verbatim_and_cleared() {
        let mut model = Model::default();
        connected(&mut model);
        model.apply(CoreUpdate::Notice {
            message: "the local-network exception cannot be verified: 10.0.0.53 is in 10.0.0.0/8"
                .to_string(),
        });
        assert!(model.notice().expect("notice").contains("10.0.0.0/8"));
        model.clear_notice();
        assert!(model.notice().is_none());
    }

    #[test]
    fn a_launch_command_is_quoted_and_cannot_smuggle_a_second_line() {
        assert_eq!(
            launch_command("/usr/bin/firefox").expect("command"),
            "exec '/usr/bin/firefox'"
        );
        assert_eq!(
            launch_command("/opt/My App/run").expect("command"),
            "exec '/opt/My App/run'"
        );
        assert_eq!(
            launch_command("/tmp/it's here").expect("command"),
            "exec '/tmp/it'\\''s here'"
        );
        assert!(launch_command("").is_err());
        assert!(launch_command("/usr/bin/firefox\nrm -rf /").is_err());
    }

    #[test]
    fn health_and_verification_are_only_ever_rendered_from_the_snapshot() {
        // A regression guard for the rule: no widget code may derive a state. The model exposes
        // the snapshot's own fields and nothing else.
        let mut model = Model::default();
        connected(&mut model);
        model.apply(CoreUpdate::Snapshot {
            epoch: 1,
            snapshot: Box::new(Snapshot {
                state: ProtectionState::Degraded,
                generation: 1,
                health: Health {
                    verification: Verification::Unavailable,
                    ..Health::default()
                },
                ..Snapshot::default()
            }),
        });
        let current = model.current().expect("current");
        assert_eq!(current.health.verification, Verification::Unavailable);
        assert_eq!(current.state, ProtectionState::Degraded);
    }
}
