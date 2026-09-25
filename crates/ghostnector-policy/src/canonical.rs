//! Canonicalising what the kernel says it holds.
//!
//! The effective-policy comparison needs the same text on both sides: what was applied and what the
//! kernel reports later. nftables prints counters with live values, which change with use and are
//! not part of the policy, so they are stripped. Everything else is compared exactly — both sides
//! come from the same formatter, so there is no brittleness to trade against precision.
//!
//! This lives here, not in one helper, because two helpers now watch two kernels: `netd` watches
//! the host ruleset and `appd` watches each namespace's. A single comparison implementation is the
//! difference between "the policy is unchanged" and "each helper's idea of unchanged".

/// Reduce a kernel ruleset listing to the part that describes policy rather than traffic.
///
/// Removes `destroy table` lines (the replacement preamble) and the numbers after `counter packets`
/// and `counter bytes`, keeping the `counter` keyword itself.
pub fn canonical_kernel_ruleset(ruleset: &str) -> String {
    let mut out = String::new();
    for line in ruleset.lines() {
        if line.trim_start().starts_with("destroy table") {
            continue;
        }
        let mut kept: Vec<&str> = Vec::new();
        let mut tokens = line.split_whitespace().peekable();
        while let Some(token) = tokens.next() {
            if (token == "packets" || token == "bytes")
                && kept.last().is_some_and(|last| *last == "counter")
            {
                tokens.next(); // the number that follows
                continue;
            }
            kept.push(token);
        }
        if kept.is_empty() {
            continue;
        }
        out.push_str(&kept.join(" "));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_not_part_of_the_policy() {
        let live = "\ttable inet ghostnector {\n\t\tcounter packets 42 bytes 900 accept\n\t}\n";
        let without = canonical_kernel_ruleset(live);
        assert!(!without.contains("42"), "{without}");
        assert!(!without.contains("900"), "{without}");
        assert!(without.contains("counter accept"), "{without}");
    }

    #[test]
    fn the_replacement_preamble_is_not_part_of_the_comparison() {
        let live = "destroy table inet ghostnector\ntable inet ghostnector {\n}\n";
        let canonical = canonical_kernel_ruleset(live);
        assert!(!canonical.contains("destroy table"), "{canonical}");
        assert!(canonical.contains("table inet ghostnector"), "{canonical}");
    }

    #[test]
    fn a_counter_inside_a_rule_keeps_its_keyword_and_loses_its_numbers() {
        let live = "        udp dport 53 counter packets 3 bytes 210 redirect to :53 comment \"DNS goes to the chokepoint\"";
        let canonical = canonical_kernel_ruleset(live);
        assert_eq!(
            canonical.trim(),
            "udp dport 53 counter redirect to :53 comment \"DNS goes to the chokepoint\""
        );
    }

    #[test]
    fn two_listings_of_the_same_policy_are_equal() {
        let first = "table inet ghostnector {\n\tcounter packets 1 bytes 2 accept\n}\n";
        let second = "table inet ghostnector {\n\tcounter packets 999 bytes 4096 accept\n}\n";
        assert_eq!(
            canonical_kernel_ruleset(first),
            canonical_kernel_ruleset(second)
        );
    }
}
