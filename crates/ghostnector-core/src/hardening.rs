//! Tests that the packaged I2P unit matches the hardening this design assumes.
//!
//! The router must be an ordinary unprivileged process: it needs no capabilities, and a unit that
//! acquired one would be a privilege widening a review has to see. The tests read the unit that
//! ships, so the property cannot drift away from the text file.

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    fn unit_file() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/systemd/ghostnector-i2pd.service");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
    }

    fn polkit_rule_file() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/polkit-1/rules.d/50-ghostnector.rules");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
    }

    fn resolved_polkit_rule_file() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/polkit-1/rules.d/51-ghostnector-resolved.rules");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
    }

    fn packaging_file(relative: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging")
            .join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
    }

    /// Every directory a tmpfiles entry creates, in the order the file lists them.
    fn tmpfiles_directories() -> Vec<String> {
        packaging_file("tmpfiles.d/ghostnector.conf")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let kind = fields.next()?;
                if !kind.starts_with('d') && !kind.starts_with('v') && !kind.starts_with('q') {
                    return None;
                }
                fields.next().map(str::to_string)
            })
            .collect()
    }

    /// A `ReadWritePaths=` entry under `/run` that nothing creates is a unit that cannot start on a
    /// fresh boot: systemd refuses to set up the unit's mount namespace when a listed path is
    /// missing (`226/NAMESPACE`). D-33 was exactly that for `/run/netns` and the namespace helper.
    #[test]
    fn every_runtime_directory_a_unit_writes_is_created_before_the_unit_starts() {
        let created = tmpfiles_directories();
        let units = [
            "ghostnector-netd.service",
            "ghostnector-core.service",
            "ghostnector-appd.service",
            "ghostnector-tor.service",
            "ghostnector-bootguard.service",
        ];
        for unit in units {
            let text = packaging_file(&format!("systemd/{unit}"));
            for line in text.lines().map(str::trim) {
                let Some(value) = line.strip_prefix("ReadWritePaths=") else {
                    continue;
                };
                for entry in value.split_whitespace() {
                    // The `-` prefix means "ignore when it does not exist"; those paths need no
                    // creator, and the unit says so explicitly.
                    let path = entry.strip_prefix('-').unwrap_or(entry);
                    if !path.starts_with("/run/") {
                        continue;
                    }
                    assert!(
                        created.iter().any(|candidate| candidate == path),
                        "{unit} lists ReadWritePaths={path}, which no tmpfiles entry creates; \
                         on a fresh boot systemd fails the unit with 226/NAMESPACE"
                    );
                }
            }
        }
    }

    /// A managed router that ignores SIGTERM must not freeze the interface for the systemd default
    /// of 90 s: two of three measured disconnects took the full default before the SIGKILL (D-51).
    /// Both routers are clients with disposable state, so a bounded stop is safe.
    #[test]
    fn a_router_that_ignores_sigterm_does_not_freeze_the_interface() {
        for unit in [
            "systemd/ghostnector-tor.service",
            "systemd/ghostnector-i2pd.service",
        ] {
            let text = packaging_file(unit);
            assert_eq!(
                line_value(&text, "TimeoutStopSec"),
                Some("20"),
                "{unit} must bound TimeoutStopSec (D-51)"
            );
        }
    }

    /// The namespace helper's start can fail for a permanent reason; it must not restart forever.
    /// Before this bound existed it was observed restarting more than a thousand times in half an
    /// hour (D-33). The keys belong in `[Unit]`: systemd ignores them in `[Service]`, which is
    /// where they were first written.
    #[test]
    fn a_unit_that_can_never_start_is_not_restarted_forever() {
        let text = packaging_file("systemd/ghostnector-appd.service");
        for key in ["StartLimitIntervalSec", "StartLimitBurst"] {
            assert_eq!(
                section_of(&text, key).as_deref(),
                Some("[Unit]"),
                "ghostnector-appd.service must bound its restarts with {key}= in [Unit] (D-33)"
            );
        }
    }

    /// The section a `key=value` line lives in, or None when the key is absent.
    fn section_of(text: &str, key: &str) -> Option<String> {
        let mut section = String::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                section = trimmed.to_string();
                continue;
            }
            if trimmed.starts_with(&format!("{key}=")) {
                return Some(section);
            }
        }
        None
    }

    /// `Documentation=` references must point at files the package actually installs. The units
    /// named man pages that were never written and a recovery file that was never installed;
    /// systemd-analyze verify reports both as broken references (D-35).
    #[test]
    fn every_documentation_reference_is_installed() {
        let installer = packaging_file("install.sh");
        let units = [
            "ghostnector-netd.service",
            "ghostnector-core.service",
            "ghostnector-appd.service",
            "ghostnector-bootguard.service",
        ];
        for unit in units {
            let text = packaging_file(&format!("systemd/{unit}"));
            for line in text.lines().map(str::trim) {
                let Some(value) = line.strip_prefix("Documentation=") else {
                    continue;
                };
                for reference in value.split_whitespace() {
                    if let Some(path) = reference.strip_prefix("file:") {
                        assert!(
                            installer.contains(path),
                            "{unit} documents {path}, which install.sh never installs (D-35)"
                        );
                    }
                }
            }
        }
    }

    /// The control plane names the default-route interface for systemd-resolved by reading
    /// `/proc/net/route`. `ProcSubset=pid` hides `/proc/net`, and with it the resolver was silently
    /// never repointed on an installed, resolved machine (D-37). `ProtectProc=invisible` stays: it
    /// hides other processes' details, which is the protection that matters, and `/proc/net` is
    /// world-readable anyway.
    #[test]
    fn the_core_unit_does_not_hide_proc_net() {
        let text = packaging_file("systemd/ghostnector-core.service");
        assert!(
            !text
                .lines()
                .map(str::trim)
                .any(|line| line.starts_with("ProcSubset=")),
            "ghostnector-core.service must not set ProcSubset: it hides /proc/net, and the resolver \
             is then never repointed (D-37)"
        );
    }

    /// systemd ignored `KeepCapabilities=` (there is no such directive) and the unit claimed a
    /// mechanism that did not exist; the capability state is real because the helper runs as root
    /// with a bounded set, and it is measured on the installed machine (D-36).
    #[test]
    fn the_units_do_not_claim_a_directive_systemd_does_not_have() {
        for unit in [
            "ghostnector-netd.service",
            "ghostnector-core.service",
            "ghostnector-appd.service",
            "ghostnector-bootguard.service",
            "ghostnector-tor.service",
            "ghostnector-i2pd.service",
        ] {
            let text = packaging_file(&format!("systemd/{unit}"));
            assert!(
                !text
                    .lines()
                    .map(str::trim)
                    .any(|line| !line.starts_with('#') && line.contains("KeepCapabilities")),
                "{unit} names KeepCapabilities, which systemd ignores (D-36)"
            );
        }
    }

    /// (path, mode, owner) for every directory a tmpfiles entry creates.
    fn tmpfiles_entries() -> Vec<(String, String, String)> {
        packaging_file("tmpfiles.d/ghostnector.conf")
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let kind = fields.next()?;
                if !kind.starts_with('d') && !kind.starts_with('v') && !kind.starts_with('q') {
                    return None;
                }
                let path = fields.next()?.to_string();
                let mode = fields.next().unwrap_or("0755").to_string();
                let owner = fields.next().unwrap_or("root").to_string();
                Some((path, mode, owner))
            })
            .collect()
    }

    /// A daemon that binds a unix socket must be able to create it: it runs without
    /// `CAP_DAC_OVERRIDE` (or as an unprivileged account), so the socket's directory has to be
    /// owned by that same account. D-29 (netd) and D-34 (the namespace helper) were both this
    /// mistake on the installed layout; the source-tree suites missed them because they ran the
    /// binaries directly, as root with every capability.
    fn socket_placement_problems(
        unit: &str,
        text: &str,
        entries: &[(String, String, String)],
    ) -> Vec<String> {
        let mut problems = Vec::new();
        let user = line_value(text, "User").unwrap_or("root").to_string();
        let tokens: Vec<&str> = text.split_whitespace().collect();
        for (index, token) in tokens.iter().enumerate() {
            if *token != "--socket" {
                continue;
            }
            let Some(raw) = tokens.get(index + 1) else {
                problems.push(format!("{unit}: --socket must be followed by a path"));
                continue;
            };
            let path = raw.trim_end_matches('\\');
            if !path.starts_with('/') {
                problems.push(format!("{unit}: --socket {path} is not absolute"));
                continue;
            }
            let parent = std::path::Path::new(path)
                .parent()
                .expect("a socket path has a parent")
                .to_string_lossy()
                .to_string();
            let Some((_, mode, owner)) = entries
                .iter()
                .find(|(candidate, _, _)| *candidate == parent)
            else {
                problems.push(format!(
                    "{unit}: --socket {path} lives in {parent}, which no tmpfiles entry creates"
                ));
                continue;
            };
            if owner != &user {
                problems.push(format!(
                    "{unit}: {parent} is owned by {owner}, but the daemon runs as {user} without \
                     CAP_DAC_OVERRIDE and could not create its socket (D-29/D-34)"
                ));
            }
            match u32::from_str_radix(mode, 8) {
                Ok(bits) if bits & 0o022 == 0 => {}
                Ok(_) => problems.push(format!(
                    "{unit}: {parent} is group- or other-writable ({mode}); the client's trust \
                     check must refuse such a socket directory"
                )),
                Err(_) => problems.push(format!("{unit}: tmpfiles mode '{mode}' is not octal")),
            }
        }
        problems
    }

    #[test]
    fn a_daemon_can_write_the_socket_it_binds() {
        let entries = tmpfiles_entries();
        let units = [
            "ghostnector-netd.service",
            "ghostnector-core.service",
            "ghostnector-appd.service",
        ];
        for unit in units {
            let text = packaging_file(&format!("systemd/{unit}"));
            let problems = socket_placement_problems(unit, &text, &entries);
            assert!(
                problems.is_empty(),
                "socket placement drifted: {problems:?}"
            );
        }
    }

    #[test]
    fn the_socket_placement_checker_notices_a_daemon_that_cannot_write_its_socket() {
        let entries = tmpfiles_entries();
        // No User= means root; the control plane's directory is owned by the control plane's
        // account, so this root daemon could not create the socket (the D-34 shape).
        let synthetic = "[Service]\nExecStart=/usr/libexec/x --socket /run/ghostnector/appd.sock\n";
        let problems =
            socket_placement_problems("ghostnector-synthetic.service", synthetic, &entries);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("CAP_DAC_OVERRIDE")),
            "{problems:?}"
        );
    }

    /// The polkit rule is the authorization for the control plane to start and stop the two router
    /// units. It is a privilege surface: it must stay bounded to that user, those units and those
    /// verbs, and this test fails if the text drifts.
    #[test]
    fn the_polkit_rule_grants_only_the_two_router_units_to_the_control_plane() {
        let text = polkit_rule_file();
        assert!(
            text.contains("org.freedesktop.systemd1.manage-units"),
            "the rule must name the manage-units action"
        );
        assert!(
            text.contains("subject.user !== \"ghostnector\""),
            "the rule must be bounded to the ghostnector service account"
        );
        assert!(text.contains("ghostnector-tor.service"));
        assert!(text.contains("ghostnector-i2pd.service"));
        for verb in ["start", "stop"] {
            assert!(
                text.contains(&format!("verb === \"{verb}\"")),
                "the rule must allow {verb}"
            );
        }
        for forbidden in ["restart", "reload", "enable", "disable", "mask", "unmask"] {
            assert!(
                !text.contains(&format!("verb === \"{forbidden}\"")),
                "the rule must not allow {forbidden}"
            );
        }
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.is_empty() {
                continue;
            }
            if line.contains(".service") {
                assert!(
                    line.contains("ghostnector-tor.service")
                        || line.contains("ghostnector-i2pd.service"),
                    "the rule names a unit it must not: {line}"
                );
            }
        }
    }

    /// The second polkit rule is the authorization for the control plane to repoint
    /// systemd-resolved at its chokepoint on connect and to revert that on disconnect (D-38). It is
    /// a privilege surface: it must stay bounded to that user and to exactly the three actions
    /// resolvectl uses, and this test fails if the text drifts.
    #[test]
    fn the_resolved_rule_grants_only_the_resolver_actions_to_the_control_plane() {
        let text = resolved_polkit_rule_file();
        assert!(
            text.contains("subject.user !== \"ghostnector\""),
            "the rule must be bounded to the ghostnector service account"
        );
        let allowed = [
            "org.freedesktop.resolve1.set-dns-servers",
            "org.freedesktop.resolve1.set-domains",
            "org.freedesktop.resolve1.revert",
            "org.freedesktop.network1.set-dns-servers",
            "org.freedesktop.network1.set-domains",
            "org.freedesktop.network1.revert-dns",
        ];
        for action in allowed {
            assert!(text.contains(action), "the rule must allow {action}");
        }
        for line in text.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.is_empty() {
                continue;
            }
            if let Some(start) = line.find("org.freedesktop.") {
                let rest = &line[start..];
                let end = rest
                    .find(|character: char| {
                        !(character.is_ascii_alphanumeric() || character == '.' || character == '-')
                    })
                    .unwrap_or(rest.len());
                let action = &rest[..end];
                assert!(
                    allowed.contains(&action),
                    "the rule names an action it must not: {action}"
                );
            }
        }
    }

    fn line_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
        text.lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
    }

    /// Everything that must be true of the unit, as a list of human-readable violations.
    fn violations(text: &str) -> Vec<String> {
        let mut problems = Vec::new();
        let expected = [
            ("User", "i2pd"),
            ("Group", "i2pd"),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("PrivateTmp", "yes"),
            ("PrivateDevices", "yes"),
            ("ProtectProc", "invisible"),
            ("ProcSubset", "pid"),
            ("StateDirectory", "ghostnector-i2pd"),
        ];
        for (key, value) in expected {
            match line_value(text, key) {
                Some(found) if found == value => {}
                Some(found) => problems.push(format!("{key} is '{found}', expected '{value}'")),
                None => problems.push(format!("{key} is missing")),
            }
        }
        if !text.contains("/usr/bin/i2pd --conf=/run/ghostnector/i2pd.conf") {
            problems
                .push("the unit does not start i2pd with the generated configuration".to_string());
        }
        // The router resolves its home from $HOME and stats `$HOME/.i2pd` before reading anything;
        // ProtectHome=yes hides /home and the package user's home does not exist, so the unit must
        // point HOME at the state directory or the router aborts at every start (D-40).
        match line_value(text, "Environment") {
            Some(found) if found.contains("HOME=/var/lib/ghostnector-i2pd") => {}
            Some(found) => problems.push(format!(
                "Environment is '{found}', expected HOME=/var/lib/ghostnector-i2pd (D-40)"
            )),
            None => problems
                .push("Environment=HOME=/var/lib/ghostnector-i2pd is missing (D-40)".to_string()),
        }
        if !text.contains("--certsdir=/usr/share/i2pd/certificates") {
            problems.push(
                "the unit does not name the package's certificate directory (D-40)".to_string(),
            );
        }
        // The router's name resolution must happen from its own uid; the unit bind-mounts the
        // resolver files the control plane writes (D-42).
        for mount in [
            "BindReadOnlyPaths=/run/ghostnector/i2pd-resolv.conf:/etc/resolv.conf",
            "BindReadOnlyPaths=/run/ghostnector/i2pd-nsswitch.conf:/etc/nsswitch.conf",
        ] {
            if !text.contains(mount) {
                problems.push(format!("the unit does not bind {mount} (D-42)"));
            }
        }
        // No capability may appear anywhere: this process needs none.
        for key in ["CapabilityBoundingSet", "AmbientCapabilities"] {
            if line_value(text, key).is_some() {
                problems.push(format!(
                    "{key} must not be present: the router needs no capabilities"
                ));
            }
        }
        problems
    }

    #[test]
    fn the_packaged_unit_is_the_designed_hardening() {
        let problems = violations(&unit_file());
        assert!(problems.is_empty(), "the unit drifted: {problems:?}");
    }

    #[test]
    fn the_checker_notices_a_unit_that_acquired_a_capability() {
        let widened = "\
[Service]
User=i2pd
Group=i2pd
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectProc=invisible
ProcSubset=pid
StateDirectory=ghostnector-i2pd
CapabilityBoundingSet=CAP_NET_ADMIN
ExecStart=/usr/bin/i2pd --conf=/run/ghostnector/i2pd.conf
";
        let problems = violations(widened);
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("CapabilityBoundingSet")),
            "{problems:?}"
        );
    }
}
