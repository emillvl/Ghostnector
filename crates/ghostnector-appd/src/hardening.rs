//! Tests that the packaged unit matches the hardening this component was designed with.
//!
//! The capability set is a security property, and a property that only lives in a text file drifts.
//! These tests read the unit that ships and refuse a version that widened it. They are deliberately
//! a small parser rather than a systemd query: they run anywhere, including a container, and they
//! compare against the *intent* in this repository.

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    fn unit_file() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/systemd/ghostnector-appd.service");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
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
            (
                "CapabilityBoundingSet",
                // Dropping to the invoking user needs CAP_SETUID/CAP_SETGID (D-46).
                "CAP_NET_ADMIN CAP_SYS_ADMIN CAP_CHOWN CAP_SETUID CAP_SETGID",
            ),
            ("AmbientCapabilities", "CAP_NET_ADMIN"),
            ("NoNewPrivileges", "yes"),
            ("RestrictAddressFamilies", "AF_UNIX AF_NETLINK"),
            ("RestrictNamespaces", "net mnt"),
            // `ip netns add` needs `mount --make-shared /run/netns`, and `mount` is not in
            // `@system-service`; without `@mount` every namespace creation failed with EPERM on
            // the installed product (D-44).
            ("SystemCallFilter", "@system-service @mount"),
            ("ProtectSystem", "strict"),
            ("ReadWritePaths", "/run/ghostnector /run/netns"),
        ];
        for (key, value) in expected {
            match line_value(text, key) {
                Some(found) if found == value => {}
                Some(found) => problems.push(format!("{key} is '{found}', expected '{value}'")),
                None => problems.push(format!("{key} is missing")),
            }
        }
        // systemd has no KeepCapabilities directive; naming one is a claim that is silently
        // ignored, so the unit text must not carry it (D-36). The capability state is real because
        // the helper runs as root with a bounded set, and it is measured on the installed machine.
        if text
            .lines()
            .map(str::trim)
            .any(|line| !line.starts_with('#') && line.contains("KeepCapabilities"))
        {
            problems.push("KeepCapabilities is not a systemd directive (D-36)".to_string());
        }
        if !text.contains("/usr/libexec/ghostnector-appd") {
            problems.push("the unit does not start the helper from /usr/libexec".to_string());
        }
        if !text.contains("/usr/libexec/ghostnector-appd-launch") {
            problems.push("the unit does not name the launch helper".to_string());
        }

        // The bounding set may contain exactly the capabilities the design names. Anything else
        // would be a widening that a review must see.
        let allowed = [
            "CAP_NET_ADMIN",
            "CAP_SYS_ADMIN",
            "CAP_CHOWN",
            "CAP_SETUID",
            "CAP_SETGID",
        ];
        if let Some(line) = line_value(text, "CapabilityBoundingSet") {
            for capability in line.split_whitespace() {
                if !allowed.contains(&capability) {
                    problems.push(format!("the bounding set contains '{capability}'"));
                }
            }
        }
        // Only CAP_NET_ADMIN may be ambient: ambient capabilities are inherited by the tools the
        // helper runs, and those tools must never hold CAP_SYS_ADMIN or CAP_CHOWN.
        if let Some(line) = line_value(text, "AmbientCapabilities") {
            for capability in line.split_whitespace() {
                if capability != "CAP_NET_ADMIN" {
                    problems.push(format!("'{capability}' must not be ambient"));
                }
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
    fn the_checker_notices_a_widened_unit() {
        // The oracle is tested too: a unit with ambient CAP_SYS_ADMIN and an extra capability must
        // be rejected by the same code that accepts the real one.
        let widened = "\
[Service]
ExecStart=/usr/libexec/ghostnector-appd
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=net
SystemCallFilter=@system-service
ProtectSystem=strict
ReadWritePaths=/run/ghostnector /run/netns
";
        let problems = violations(widened);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("'CAP_SYS_ADMIN' must not be ambient")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("CAP_DAC_OVERRIDE")),
            "{problems:?}"
        );
    }

    #[test]
    fn the_checker_notices_a_directive_that_does_not_exist() {
        let with_bogus = "[Service]\nKeepCapabilities=yes\n";
        let problems = violations(with_bogus);
        assert!(
            problems
                .iter()
                .any(|p| p.contains("not a systemd directive")),
            "{problems:?}"
        );
    }

    #[test]
    fn the_tmpfiles_entry_keeps_the_group_files_private() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/tmpfiles.d/ghostnector.conf");
        let text = std::fs::read_to_string(&path).expect("tmpfiles entry");
        // The group may traverse `apps` (each group's session socket lives inside it and the
        // invoking user must reach it, D-45) but may not list or write it.
        assert!(
            text.lines()
                .any(|line| line.starts_with("d /run/ghostnector/apps 0710 root ghostnector")),
            "{text}"
        );
    }
}
