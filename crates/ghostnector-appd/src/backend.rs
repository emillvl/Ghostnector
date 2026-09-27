//! Creating and inspecting dead-end namespaces.
//!
//! Everything here is names derived from an id and typed values from configuration. No name, path,
//! address, or ruleset ever comes from a client.
//!
//! ## Why `CAP_SYS_ADMIN` is needed, precisely
//!
//! Two operations require it, and the M8.2 gate demonstrates both empirically by running this
//! helper with the capability dropped:
//!
//! * creating a network namespace (`unshare(CLONE_NEWNET)` via `ip netns add`), and
//! * entering one (`setns`) to install and verify its ruleset.
//!
//! Everything else — links, addresses, routes, bridge membership, per-namespace sysctls — needs only
//! `CAP_NET_ADMIN`, which is also the only capability this helper's child tools inherit. The
//! helper holds `CAP_SYS_ADMIN` itself (it runs as root under a bounded capability set) but never
//! passes it to a child, so a compromised `nft` or `ip` does not get it.

use std::collections::HashMap;
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ghostnector_spec::app::{APP_LINK_PREFIX, APP_NETNS_PREFIX, APP_RELAY_PORT, MAX_APP_GROUPS};
use ghostnector_spec::appd::{CheckVerdict, ProbeConfig};
use ghostnector_spec::backend::Ports;
use nix::sched::{setns, CloneFlags};

/// Where `ip netns` keeps its named namespaces (iproute2's fixed choice).
pub const NETNS_DIR: &str = "/run/netns";

/// The name of the link inside a namespace. Fixed: the app cannot name it and neither can a client.
pub const APP_LINK: &str = "ghlink0";

/// The temporary name of a veth peer while it is being moved into a namespace.
pub fn peer_name(id: u32) -> String {
    format!("ghpeer{id}")
}

/// The name of a group's namespace.
pub fn netns_name(id: u32) -> Result<String, BackendError> {
    bounded(id)?;
    Ok(format!("{APP_NETNS_PREFIX}{id}"))
}

/// The name of a group's host-side link.
pub fn host_link(id: u32) -> Result<String, BackendError> {
    bounded(id)?;
    Ok(format!("{APP_LINK_PREFIX}{id}"))
}

fn bounded(id: u32) -> Result<(), BackendError> {
    if id == 0 || id as usize > MAX_APP_GROUPS {
        return Err(BackendError::Refused(format!(
            "group id {id} is outside 1..={MAX_APP_GROUPS}"
        )));
    }
    Ok(())
}

/// Everything the backend needs to create or verify one group. Built by the server from its own
/// configuration and the registry; never assembled from client input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRequest {
    /// The group's id.
    pub id: u32,
    /// The user the group belongs to; the relay runs as this uid.
    pub owner_uid: u32,
    /// The address assigned inside the namespace.
    pub address: Ipv4Addr,
    /// The bridge carrying app links.
    pub bridge: String,
    /// The host-local core address.
    pub core: Ipv4Addr,
    /// The APP address-space prefix.
    pub prefix: u8,
    /// The dead-end device each namespace's default route points at.
    pub dead_device: String,
    /// The ports the namespace rules name.
    pub ports: Ports,
    /// Where the group's own files live (the resolver configuration for the launcher).
    pub state_dir: PathBuf,
}

/// Why a kernel operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// A tool is missing, not a regular file, or writable by someone other than root.
    #[error("tool '{}' is not usable: {reason}", path.display())]
    ToolUnusable {
        /// The rejected path.
        path: PathBuf,
        /// Why it was rejected.
        reason: String,
    },
    /// A tool refused the operation.
    #[error("{tool}: {reason}")]
    Command {
        /// The tool.
        tool: String,
        /// What it said.
        reason: String,
    },
    /// The helper could not run a tool at all.
    #[error("running '{}' failed: {reason}", path.display())]
    Io {
        /// The tool or path.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// A request was refused before touching the kernel.
    #[error("{0}")]
    Refused(String),
    /// The helper could not enter a namespace. This is where a missing `CAP_SYS_ADMIN` shows up.
    #[error("cannot enter namespace '{name}': {reason}")]
    Namespace {
        /// The namespace.
        name: String,
        /// Why.
        reason: String,
    },
}

/// The kernel-facing operations the helper needs.
pub trait Namespaces: Send + Sync {
    /// Whether the bridge exists with the core address.
    fn bridge_present(&self) -> Result<bool, BackendError>;
    /// Idempotently create the bridge and give it the core address.
    fn ensure_bridge(&self) -> Result<(), BackendError>;
    /// Remove the bridge. Idempotent.
    fn destroy_bridge(&self) -> Result<(), BackendError>;
    /// Whether the group's namespace and link both exist.
    fn group_present(&self, id: u32) -> Result<bool, BackendError>;
    /// Create the whole group: namespace, link, routes, sysctls, the namespace policy, and the
    /// group's transparent relay.
    fn create(&self, request: &GroupRequest) -> Result<(), BackendError>;
    /// Destroy the group. Idempotent. Stops the relay first, so no process survives.
    fn destroy(&self, id: u32) -> Result<(), BackendError>;
    /// Start the group's transparent relay inside its namespace (called by `create`).
    fn start_relay(&self, request: &GroupRequest) -> Result<(), BackendError>;
    /// Stop and reap the group's relay (called by `destroy`).
    fn stop_relay(&self, id: u32);
    /// The kernel's own report of the namespace's ruleset, or an empty string when absent.
    fn applied_policy(&self, id: u32) -> Result<String, BackendError>;
    /// Run the fixed verification probe inside one group, as an unprivileged user.
    fn probe(
        &self,
        id: u32,
        uid: u32,
        config: &ProbeConfig,
    ) -> Result<Vec<CheckVerdict>, BackendError>;
    /// Everything about the namespace's shape that differs from what was installed. Empty means the
    /// shape is exactly right.
    fn shape_problems(&self, request: &GroupRequest) -> Result<Vec<String>, BackendError>;
}

/// The external tools the helper runs. Every one is verified (root-owned, not writable by anyone
/// else) before the helper serves anything.
#[derive(Debug, Clone)]
pub struct Tools {
    /// Absolute path to `nft`.
    pub nft: PathBuf,
    /// Absolute path to `ip`.
    pub ip: PathBuf,
    /// Absolute path to `bridge` (used only for port isolation).
    pub bridge_ctl: PathBuf,
    /// Absolute path to the fixed verification probe.
    pub probe: PathBuf,
    /// Absolute path to the per-namespace transparent relay.
    pub relay: PathBuf,
}

/// A group's running relay: its pid, and the write end of the pipe whose close stops it. The
/// packaged capability set has no `CAP_KILL`, and the relay holds its namespace open, so this pipe
/// is the shutdown channel (see `bin/relay.rs`).
#[derive(Debug)]
struct RelayHandle {
    pid: u32,
    control: Option<ChildStdin>,
}

/// The real backend: `ip`, `bridge`, `nft`, and the per-namespace sysctl files.
#[derive(Debug)]
pub struct SystemNamespaces {
    nft: PathBuf,
    ip: PathBuf,
    bridge_ctl: PathBuf,
    probe: PathBuf,
    relay: PathBuf,
    bridge: String,
    core: Ipv4Addr,
    prefix: u8,
    /// Serialises namespace entry: one thread is inside a namespace at a time.
    namespace_lock: Mutex<()>,
    /// The transparent relay each group is running, by group id.
    relays: Mutex<HashMap<u32, RelayHandle>>,
}

impl SystemNamespaces {
    /// Verify the tools and build the backend.
    pub fn new(
        tools: Tools,
        bridge: String,
        core: Ipv4Addr,
        prefix: u8,
    ) -> Result<Self, BackendError> {
        check_tool(&tools.nft)?;
        check_tool(&tools.ip)?;
        check_tool(&tools.bridge_ctl)?;
        check_tool(&tools.probe)?;
        check_tool(&tools.relay)?;
        Ok(Self {
            nft: tools.nft,
            ip: tools.ip,
            bridge_ctl: tools.bridge_ctl,
            probe: tools.probe,
            relay: tools.relay,
            bridge,
            core,
            prefix,
            namespace_lock: Mutex::new(()),
            relays: Mutex::new(HashMap::new()),
        })
    }

    fn run(&self, tool: &Path, args: &[&str]) -> Result<String, BackendError> {
        self.run_with_stdin(tool, args, None)
    }

    fn run_with_stdin(
        &self,
        tool: &Path,
        args: &[&str],
        input: Option<&str>,
    ) -> Result<String, BackendError> {
        let mut child = Command::new(tool)
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| BackendError::Io {
                path: tool.to_path_buf(),
                reason: error.to_string(),
            })?;
        if let Some(input) = input {
            let mut stdin = child.stdin.take().ok_or_else(|| BackendError::Io {
                path: tool.to_path_buf(),
                reason: "the tool did not accept input".to_string(),
            })?;
            stdin
                .write_all(input.as_bytes())
                .map_err(|error| BackendError::Io {
                    path: tool.to_path_buf(),
                    reason: error.to_string(),
                })?;
        }
        let output = child.wait_with_output().map_err(|error| BackendError::Io {
            path: tool.to_path_buf(),
            reason: error.to_string(),
        })?;
        if !output.status.success() {
            return Err(BackendError::Command {
                tool: tool.display().to_string(),
                reason: describe_failure(&output.stderr, output.status.code()),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    /// Run a tool for real only if it says the object exists; "not found" is not an error here.
    fn exists(&self, args: &[&str]) -> Result<bool, BackendError> {
        match self.run(&self.ip, args) {
            Ok(_) => Ok(true),
            Err(BackendError::Command { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Enter a namespace, run the closure, and always come back.
    ///
    /// `setns(CLONE_NEWNET)` needs `CAP_SYS_ADMIN`. The lock keeps one thread inside a foreign
    /// namespace at a time; the original namespace is restored even when the closure fails.
    fn with_namespace<T>(
        &self,
        name: &str,
        body: impl FnOnce() -> Result<T, BackendError>,
    ) -> Result<T, BackendError> {
        let _guard = self
            .namespace_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let target = std::fs::File::open(format!("{NETNS_DIR}/{name}")).map_err(|error| {
            BackendError::Namespace {
                name: name.to_string(),
                reason: error.to_string(),
            }
        })?;
        let original =
            std::fs::File::open("/proc/self/ns/net").map_err(|error| BackendError::Namespace {
                name: name.to_string(),
                reason: format!("cannot open the original namespace: {error}"),
            })?;
        setns(&target, CloneFlags::CLONE_NEWNET).map_err(|error| BackendError::Namespace {
            name: name.to_string(),
            reason: error.to_string(),
        })?;

        let result = body();
        let restored = setns(&original, CloneFlags::CLONE_NEWNET);
        match (result, restored) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(error)) => Err(BackendError::Namespace {
                name: name.to_string(),
                reason: format!("could not return to the original namespace: {error}"),
            }),
            (Err(error), _) => Err(error),
        }
    }

    fn write_sysctl(&self, relative: &str, value: &str) -> Result<(), BackendError> {
        let path = PathBuf::from("/proc/sys").join(relative);
        std::fs::write(&path, value).map_err(|error| BackendError::Io {
            path,
            reason: error.to_string(),
        })
    }

    fn read_sysctl(&self, relative: &str) -> Result<String, BackendError> {
        let path = PathBuf::from("/proc/sys").join(relative);
        std::fs::read_to_string(&path)
            .map(|value| value.trim().to_string())
            .map_err(|error| BackendError::Io {
                path,
                reason: error.to_string(),
            })
    }

    fn bridge_ctl(&self, args: &[&str]) -> Result<(), BackendError> {
        self.run(&self.bridge_ctl, args).map(|_| ())
    }

    fn namespace_policy(&self, request: &GroupRequest) -> Result<String, BackendError> {
        let environment = ghostnector_policy::Environment {
            tor_uid: None,
            dnscrypt_uid: None,
            i2p_uid: None,
            i2p_http_port: ghostnector_spec::backend::I2pPorts::default().http,
            i2p_socks_port: ghostnector_spec::backend::I2pPorts::default().socks,
            trans_port: request.ports.trans,
            chokepoint_port: request.ports.chokepoint,
            socks_port: request.ports.socks,
            dhcp_client_port: 68,
            app_core: request.core,
            app_prefix: request.prefix,
            app_bridge: request.bridge.clone(),
        };
        let policy = ghostnector_policy::compile_app_namespace(&environment)
            .map_err(|error| BackendError::Refused(error.to_string()))?;
        Ok(ghostnector_policy::render_replace_script(&policy.ruleset))
    }

    fn write_resolver_config(&self, request: &GroupRequest) -> Result<(), BackendError> {
        let directory = request.state_dir.join(request.id.to_string());
        std::fs::create_dir_all(&directory).map_err(|error| BackendError::Io {
            path: directory.clone(),
            reason: error.to_string(),
        })?;
        let path = directory.join("resolv.conf");
        std::fs::write(&path, format!("nameserver {}\n", request.core)).map_err(|error| {
            BackendError::Io {
                path: path.clone(),
                reason: error.to_string(),
            }
        })?;
        Ok(())
    }

    fn interface_names(&self, output: &str) -> Vec<String> {
        output
            .lines()
            .filter_map(|line| {
                // `ip -o link show` lines look like `2: ghlink0@if5: <...>`.
                let (_, rest) = line.split_once(": ")?;
                let name = rest.split(':').next()?;
                let name = name.split('@').next()?;
                Some(name.trim().to_string())
            })
            .collect()
    }

    fn addresses(&self, output: &str) -> Vec<String> {
        output
            .lines()
            .flat_map(|line| {
                let mut tokens = line.split_whitespace();
                let mut found = Vec::new();
                while let Some(token) = tokens.next() {
                    if token == "inet" {
                        if let Some(address) = tokens.next() {
                            found.push(address.to_string());
                        }
                    }
                }
                found
            })
            .collect()
    }
}

impl Namespaces for SystemNamespaces {
    fn bridge_present(&self) -> Result<bool, BackendError> {
        self.exists(&["link", "show", "dev", &self.bridge])
    }

    fn ensure_bridge(&self) -> Result<(), BackendError> {
        if !self.bridge_present()? {
            self.run(&self.ip, &["link", "add", &self.bridge, "type", "bridge"])?;
        }
        let address = format!("{}/{}", self.core, self.prefix);
        self.run(
            &self.ip,
            &["addr", "replace", &address, "dev", &self.bridge],
        )?;
        self.run(&self.ip, &["link", "set", &self.bridge, "up"])?;
        // The bridge answers for the core address and never proxies for a destination: an
        // un-rewritten packet must not find a next hop through it (M8 decision 1).
        self.write_sysctl(&format!("net/ipv4/conf/{}/proxy_arp", self.bridge), "0")?;
        Ok(())
    }

    fn destroy_bridge(&self) -> Result<(), BackendError> {
        // Idempotent: deleting a bridge that is not there is not a failure.
        let _ = self.run(&self.ip, &["link", "del", &self.bridge]);
        Ok(())
    }

    fn group_present(&self, id: u32) -> Result<bool, BackendError> {
        let name = netns_name(id)?;
        let link = host_link(id)?;
        Ok(Path::new(&format!("{NETNS_DIR}/{name}")).exists()
            && self.exists(&["link", "show", "dev", &link])?)
    }

    fn create(&self, request: &GroupRequest) -> Result<(), BackendError> {
        let name = netns_name(request.id)?;
        let link = host_link(request.id)?;
        let peer = peer_name(request.id);
        if !self.bridge_present()? {
            return Err(BackendError::Refused(
                "the bridge has not been ensured".to_string(),
            ));
        }

        // 1. The namespace.
        self.run(&self.ip, &["netns", "add", &name])?;

        // 2. The link, moved into the namespace.
        self.run(
            &self.ip,
            &["link", "add", &link, "type", "veth", "peer", "name", &peer],
        )?;
        let moved = self.run(&self.ip, &["link", "set", &peer, "netns", &name]);
        if let Err(error) = moved {
            // Leave nothing half-created behind.
            let _ = self.run(&self.ip, &["link", "del", &link]);
            let _ = self.run(&self.ip, &["netns", "del", &name]);
            return Err(error);
        }

        // 3. The host side: a bridge port, isolated from every other port, never a proxy.
        let host_side = (|| -> Result<(), BackendError> {
            self.run(&self.ip, &["link", "set", &link, "master", &self.bridge])?;
            self.bridge_ctl(&["link", "set", "dev", &link, "isolated", "on"])?;
            self.run(&self.ip, &["link", "set", &link, "up"])?;
            self.write_sysctl(&format!("net/ipv4/conf/{link}/proxy_arp"), "0")?;
            Ok(())
        })();
        if let Err(error) = host_side {
            let _ = self.destroy(request.id);
            return Err(error);
        }

        // 4. The namespace itself, then its policy.
        let inside = self.with_namespace(&name, || {
            self.run(&self.ip, &["link", "set", "lo", "up"])?;
            self.run(&self.ip, &["link", "set", &peer, "name", APP_LINK])?;
            self.run(&self.ip, &["link", "set", APP_LINK, "up"])?;
            self.run(
                &self.ip,
                &[
                    "addr",
                    "add",
                    &format!("{}/32", request.address),
                    "dev",
                    APP_LINK,
                ],
            )?;
            self.run(
                &self.ip,
                &[
                    "route",
                    "add",
                    &format!("{}/32", request.core),
                    "dev",
                    APP_LINK,
                ],
            )?;

            // The dead end: a device with no peer. A flushed ruleset routes here and dies.
            self.run(
                &self.ip,
                &["link", "add", &request.dead_device, "type", "dummy"],
            )?;
            self.run(&self.ip, &["link", "set", &request.dead_device, "up"])?;
            self.run(
                &self.ip,
                &["route", "add", "default", "dev", &request.dead_device],
            )?;

            // No IPv6 and no redirects: nothing to leak and nothing to be redirected by.
            self.write_sysctl("net/ipv6/conf/all/disable_ipv6", "1")?;
            self.write_sysctl("net/ipv6/conf/default/disable_ipv6", "1")?;
            self.write_sysctl("net/ipv4/conf/all/accept_redirects", "0")?;
            self.write_sysctl("net/ipv4/conf/all/send_redirects", "0")?;

            let script = self.namespace_policy(request)?;
            self.run_with_stdin(&self.nft, &["-f", "-"], Some(&script))?;
            Ok(())
        });
        if let Err(error) = inside {
            let _ = self.destroy(request.id);
            return Err(error);
        }

        // 5. What the launcher will bind-mount as the namespace's resolver configuration.
        if let Err(error) = self.write_resolver_config(request) {
            let _ = self.destroy(request.id);
            return Err(error);
        }

        // 6. The namespace's transparent relay, as the application's own uid. It starts only after
        //    the policy is in force, so it can reach nothing but the core's SOCKS listener; if it
        //    does not come up the group is destroyed rather than left half-usable (D-50).
        if let Err(error) = self.start_relay(request) {
            let _ = self.destroy(request.id);
            return Err(error);
        }
        Ok(())
    }

    fn destroy(&self, id: u32) -> Result<(), BackendError> {
        let name = netns_name(id)?;
        let link = host_link(id)?;
        // Deleting either side of the veth removes both; deleting the namespace removes the rest.
        // The relay's sockets live in that namespace, so this is also what makes it exit: the
        // packaged capability set has no CAP_KILL, and a relay this process may not signal still
        // dies when its namespace does.
        let _ = self.run(&self.ip, &["link", "del", &link]);
        let _ = self.run(&self.ip, &["netns", "del", &name]);
        self.stop_relay(id);
        Ok(())
    }

    /// Start the group's transparent relay inside its namespace, as the application's uid.
    fn start_relay(&self, request: &GroupRequest) -> Result<(), BackendError> {
        let name = netns_name(request.id)?;
        let directory = request.state_dir.join(request.id.to_string());
        let _ = std::fs::create_dir_all(&directory);
        let log = directory.join("relay.log");
        let stdout = std::fs::File::create(&log)
            .map(Stdio::from)
            .unwrap_or(Stdio::null());
        let stderr = std::fs::OpenOptions::new()
            .append(true)
            .open(&log)
            .map(Stdio::from)
            .unwrap_or(Stdio::null());
        let child = Command::new(&self.ip)
            .arg("netns")
            .arg("exec")
            .arg(&name)
            .arg(&self.relay)
            .arg("--id")
            .arg(request.id.to_string())
            .arg("--uid")
            .arg(request.owner_uid.to_string())
            .arg("--listen-port")
            .arg(APP_RELAY_PORT.to_string())
            .arg("--core")
            .arg(self.core.to_string())
            .arg("--socks-port")
            .arg(request.ports.socks.to_string())
            .arg("--source")
            .arg(request.address.to_string())
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .map_err(|error| BackendError::Io {
                path: self.relay.clone(),
                reason: error.to_string(),
            })?;
        let mut child = child;
        let pid = child.id();
        let control = child.stdin.take();
        self.relays
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(request.id, RelayHandle { pid, control });

        // Wait until it accepts connections on the namespace's loopback. A relay that cannot come
        // up means the group has no usable path, so the caller destroys it.
        let name = netns_name(request.id)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let listening = self.with_namespace(&name, || {
                std::net::TcpStream::connect_timeout(
                    &std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, APP_RELAY_PORT)),
                    Duration::from_millis(500),
                )
                .map(|_| ())
                .map_err(|error| {
                    BackendError::Refused(format!("the relay is not listening: {error}"))
                })
            });
            if listening.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(BackendError::Refused(
                    "the namespace relay did not start".to_string(),
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Stop and reap the group's relay, so no process survives the group.
    ///
    /// The SIGTERM is polite and may be refused: the packaged capability set does not include
    /// `CAP_KILL`, so the helper cannot signal a process that has dropped to the application's uid.
    /// The caller deletes the namespace first, which closes the relay's sockets and makes it exit;
    /// this then reaps it with a bounded wait (never an unbounded one — a relay that somehow
    /// lingers must not hang the helper).
    fn stop_relay(&self, id: u32) {
        let handle = self
            .relays
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&id);
        let Some(handle) = handle else {
            return;
        };
        // Closing the pipe is the shutdown channel: the relay sees end-of-file on its standard
        // input and exits, with no capability required.
        drop(handle.control);
        let pid = nix::unistd::Pid::from_raw(handle.pid as i32);
        let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
        for _ in 0..50 {
            match nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                _ => return,
            }
        }
    }

    fn applied_policy(&self, id: u32) -> Result<String, BackendError> {
        let name = netns_name(id)?;
        if !Path::new(&format!("{NETNS_DIR}/{name}")).exists() {
            return Ok(String::new());
        }
        self.with_namespace(&name, || {
            match self.run(&self.nft, &["list", "table", "inet", "ghostnector"]) {
                Ok(listing) => Ok(listing),
                Err(BackendError::Command { .. }) => Ok(String::new()),
                Err(error) => Err(error),
            }
        })
    }

    fn probe(
        &self,
        id: u32,
        uid: u32,
        config: &ProbeConfig,
    ) -> Result<Vec<CheckVerdict>, BackendError> {
        let name = netns_name(id)?;
        if !Path::new(&format!("{NETNS_DIR}/{name}")).exists() {
            return Err(BackendError::Refused(
                "the namespace is missing".to_string(),
            ));
        }
        let encoded = serde_json::to_vec(config).map_err(|error| BackendError::Io {
            path: self.probe.clone(),
            reason: error.to_string(),
        })?;
        let mut child = Command::new(&self.probe)
            .arg("--id")
            .arg(id.to_string())
            .arg("--uid")
            .arg(uid.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| BackendError::Io {
                path: self.probe.clone(),
                reason: error.to_string(),
            })?;
        {
            let mut stdin = child.stdin.take().ok_or_else(|| BackendError::Io {
                path: self.probe.clone(),
                reason: "the probe did not accept input".to_string(),
            })?;
            stdin
                .write_all(&encoded)
                .map_err(|error| BackendError::Io {
                    path: self.probe.clone(),
                    reason: error.to_string(),
                })?;
        }

        // A probe that hangs must not hold the helper: the budget is the check timeout plus slack.
        let deadline = Instant::now()
            + Duration::from_secs(config.timeout_seconds.clamp(1, 60).saturating_add(10));
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BackendError::Refused(
                        "the probe did not finish within its budget".to_string(),
                    ));
                }
                Err(error) => {
                    return Err(BackendError::Io {
                        path: self.probe.clone(),
                        reason: error.to_string(),
                    })
                }
            }
        }

        let output = child.wait_with_output().map_err(|error| BackendError::Io {
            path: self.probe.clone(),
            reason: error.to_string(),
        })?;
        if !output.status.success() {
            return Err(BackendError::Command {
                tool: self.probe.display().to_string(),
                reason: describe_failure(&output.stderr, output.status.code()),
            });
        }
        serde_json::from_slice::<Vec<CheckVerdict>>(&output.stdout).map_err(|error| {
            BackendError::Command {
                tool: self.probe.display().to_string(),
                reason: format!("the probe's answer was unreadable: {error}"),
            }
        })
    }

    fn shape_problems(&self, request: &GroupRequest) -> Result<Vec<String>, BackendError> {
        let mut problems = Vec::new();
        let name = netns_name(request.id)?;
        let link = host_link(request.id)?;
        if !Path::new(&format!("{NETNS_DIR}/{name}")).exists() {
            return Ok(vec!["the namespace is missing".to_string()]);
        }
        if !self.exists(&["link", "show", "dev", &link])? {
            return Ok(vec!["the host-side link is missing".to_string()]);
        }

        // The link is a bridge port and nothing else can reach it.
        let link_description = self.run(&self.ip, &["-o", "link", "show", "dev", &link])?;
        if !link_description.contains(&format!("master {}", request.bridge)) {
            problems.push(format!(
                "the host link is not enslaved to '{}'",
                request.bridge
            ));
        }
        for interface in [link.as_str(), request.bridge.as_str()] {
            let proxy_arp = self.read_sysctl(&format!("net/ipv4/conf/{interface}/proxy_arp"))?;
            if proxy_arp != "0" {
                problems.push(format!(
                    "proxy_arp is '{proxy_arp}' on '{interface}'; it must be 0 so an un-rewritten \
                     destination has no next hop"
                ));
            }
        }

        self.with_namespace(&name, || {
            let interfaces = self.interface_names(&self.run(&self.ip, &["-o", "link", "show"])?);
            let mut expected = vec![
                APP_LINK.to_string(),
                "lo".to_string(),
                request.dead_device.clone(),
            ];
            expected.sort();
            let mut actual = interfaces.clone();
            actual.sort();
            if actual != expected {
                problems.push(format!(
                    "the namespace has interfaces {actual:?}; expected {expected:?}"
                ));
            }

            let addresses = self.addresses(&self.run(&self.ip, &["-o", "addr", "show"])?);
            if !addresses
                .iter()
                .any(|address| address == &format!("{}/32", request.address))
            {
                problems.push(format!(
                    "the app address {}/32 is not configured: {addresses:?}",
                    request.address
                ));
            }

            let routes = self.run(&self.ip, &["route", "show"])?;
            if !routes.contains(&format!("{} dev {APP_LINK}", request.core)) {
                problems.push(format!(
                    "there is no route to the core address {APP_LINK}: {routes}"
                ));
            }
            if !routes
                .lines()
                .any(|line| line.starts_with("default") && line.contains(&request.dead_device))
            {
                problems.push(format!(
                    "the default route does not terminate on '{}': {routes}",
                    request.dead_device
                ));
            }

            let ipv6 = self.read_sysctl("net/ipv6/conf/all/disable_ipv6")?;
            if ipv6 != "1" {
                problems.push(format!("IPv6 is not disabled in the namespace: '{ipv6}'"));
            }
            Ok(())
        })?;

        Ok(problems)
    }
}

/// A tool must be absolute, a regular file, root-owned, and not writable by group or others: an
/// absolute path is only meaningful if the file behind it cannot be replaced.
///
/// Public so the binary can verify the launch helper before serving a single request.
pub fn check_tool(path: &Path) -> Result<(), BackendError> {
    let reject = |reason: String| BackendError::ToolUnusable {
        path: path.to_path_buf(),
        reason,
    };
    if !path.is_absolute() {
        return Err(reject("expected an absolute path".to_string()));
    }
    let metadata = std::fs::metadata(path).map_err(|error| reject(error.to_string()))?;
    if !metadata.is_file() {
        return Err(reject("not a regular file".to_string()));
    }
    if metadata.uid() != 0 {
        return Err(reject(format!("owned by uid {}, not root", metadata.uid())));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(reject(
            "writable by group or others, so it cannot be trusted with privileges".to_string(),
        ));
    }
    Ok(())
}

/// Keep a tool's complaint short, printable, and free of control characters.
fn describe_failure(stderr: &[u8], code: Option<i32>) -> String {
    let text = String::from_utf8_lossy(stderr);
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        format!("the tool exited with status {}", code.unwrap_or(-1))
    } else {
        trimmed.chars().take(2048).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_names_are_generated_and_bounded() {
        assert_eq!(netns_name(1).unwrap(), "ghapp1");
        assert_eq!(netns_name(32).unwrap(), "ghapp32");
        assert_eq!(host_link(7).unwrap(), "ghav7");
        for bad in [0, 33, u32::MAX] {
            assert!(netns_name(bad).is_err(), "{bad}");
            assert!(host_link(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_relative_or_missing_tool_is_refused() {
        assert!(matches!(
            check_tool(Path::new("nft")),
            Err(BackendError::ToolUnusable { .. })
        ));
        assert!(matches!(
            check_tool(Path::new("/definitely/not/here")),
            Err(BackendError::ToolUnusable { .. })
        ));
        assert!(matches!(
            check_tool(Path::new("/usr/sbin")),
            Err(BackendError::ToolUnusable { .. })
        ));
    }

    #[test]
    fn failures_are_trimmed_and_printable() {
        let message = describe_failure(b"line one\nline two\x07\n\n", Some(1));
        assert_eq!(message, "line one line two");
        assert_eq!(
            describe_failure(b"", Some(2)),
            "the tool exited with status 2"
        );
    }
}
