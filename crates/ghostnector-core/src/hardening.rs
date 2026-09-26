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

    /// The namespace helper's start can fail for a permanent reason; it must not restart forever.
    /// Before this bound existed it was observed restarting more than a thousand times in half an
    /// hour (D-33).
    #[test]
    fn a_unit_that_can_never_start_is_not_restarted_forever() {
        let text = packaging_file("systemd/ghostnector-appd.service");
        for key in ["StartLimitIntervalSec", "StartLimitBurst"] {
            assert!(
                text.lines()
                    .any(|line| line.trim().starts_with(&format!("{key}="))),
                "ghostnector-appd.service must bound its restarts with {key}= (D-33)"
            );
        }
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
