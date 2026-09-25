//! Tests that the packaged unit matches the hardening this component was designed with.
//!
//! The privileged surface is a security property, and a property that only lives in a text file
//! drifts. These tests read the unit that ships and refuse a version that widened it — including a
//! version that added `CAP_SYS_ADMIN` back for namespace work, which the M8 architecture explicitly
//! assigns to `ghostnector-appd` instead (risk R7).

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    fn unit_file() -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/systemd/ghostnector-netd.service");
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
            ("CapabilityBoundingSet", "CAP_NET_ADMIN CAP_CHOWN"),
            ("AmbientCapabilities", "CAP_NET_ADMIN"),
            ("NoNewPrivileges", "yes"),
            ("RestrictAddressFamilies", "AF_UNIX AF_NETLINK"),
            ("RestrictNamespaces", "yes"),
            ("SystemCallFilter", "@system-service"),
            ("ProtectSystem", "strict"),
            ("ReadWritePaths", "/run/ghostnector /var/lib/ghostnector"),
        ];
        for (key, value) in expected {
            match line_value(text, key) {
                Some(found) if found == value => {}
                Some(found) => problems.push(format!("{key} is '{found}', expected '{value}'")),
                None => problems.push(format!("{key} is missing")),
            }
        }
        if !text.contains("/usr/libexec/ghostnector-netd") {
            problems.push("the unit does not start the helper from /usr/libexec".to_string());
        }

        // Exactly two capabilities are allowed: the policy one and the socket handoff one. Anything
        // else is a widening a review must see; `CAP_SYS_ADMIN` in particular belongs to appd.
        let allowed = ["CAP_NET_ADMIN", "CAP_CHOWN"];
        if let Some(line) = line_value(text, "CapabilityBoundingSet") {
            for capability in line.split_whitespace() {
                if !allowed.contains(&capability) {
                    problems.push(format!("the bounding set contains '{capability}'"));
                }
            }
        }
        if let Some(line) = line_value(text, "CapabilityBoundingSet") {
            if line.split_whitespace().any(|cap| cap == "CAP_SYS_ADMIN") {
                problems.push(
                    "CAP_SYS_ADMIN belongs to ghostnector-appd; netd must not hold it".to_string(),
                );
            }
        }
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
        // The oracle is tested too: ambient CAP_CHOWN, a namespace capability, and an extra
        // capability must each be reported by the same code that accepts the real unit.
        let widened = "\
[Service]
ExecStart=/usr/libexec/ghostnector-netd
CapabilityBoundingSet=CAP_NET_ADMIN CAP_CHOWN CAP_SYS_ADMIN CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_CHOWN
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=yes
SystemCallFilter=@system-service
ProtectSystem=strict
ReadWritePaths=/run/ghostnector /var/lib/ghostnector
";
        let problems = violations(widened);
        assert!(
            problems.iter().any(|p| p.contains("CAP_SYS_ADMIN")),
            "{problems:?}"
        );
        assert!(
            problems.iter().any(|p| p.contains("CAP_DAC_OVERRIDE")),
            "{problems:?}"
        );
        assert!(
            problems
                .iter()
                .any(|p| p.contains("'CAP_CHOWN' must not be ambient")),
            "{problems:?}"
        );
    }
}
