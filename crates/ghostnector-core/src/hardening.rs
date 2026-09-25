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
