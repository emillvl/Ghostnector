#!/usr/bin/env python3
"""Attribute captured packets to the protection state in force at their timestamp.

The old oracle sampled a packet count and the reported state together every ~0.2 s and blamed an
increase on the state of the *later* sample. On a machine whose Off -> Applying -> Degraded
transition takes most of a second, packets that crossed while the machine was still legitimately
off were blamed on the first protected sample: a false contradiction, and the reverse (a real
crossing inside a protected window) could only be guessed at.

This oracle is per-packet. The harness records every state change as a subscriber sees it, with a
timestamp; `tcpdump -tt` gives every captured packet a timestamp on the same clock. A packet is a
violation exactly when a protected state was in force at the packet's own timestamp.

Inputs:
    argv[1]  a state log of "<epoch>|<state line>" records (written on every StateChanged)
    stdin    "tcpdump -tt" output: "<epoch>.<us> <packet description>" lines

Output: one line per violation. Empty output means: every captured packet either crossed while the
machine was not claiming protection, or there were no captured packets at all. A packet with no
state record at or before its timestamp is reported as unattributed -- ambiguity is never a pass.
"""

import sys


def load_states(path):
    states = []
    with open(path) as handle:
        for line in handle:
            line = line.rstrip("\n")
            when, _, text = line.partition("|")
            try:
                when = float(when)
            except ValueError:
                continue
            states.append((when, text))
    states.sort(key=lambda item: item[0])
    return states


def protected(text):
    """The daemon's own words for a protection claim, and only those."""
    return ("protected, but unverified" in text) or ("and verified" in text)


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: watch-oracle.py <state-log>\n")
        return 2

    states = load_states(argv[1])
    findings = []

    if not states:
        # No timeline means the observation never started; that is not a pass.
        print("no state timeline was recorded, so nothing can be attributed")
        return 0

    # The window opens with the first recorded state. Packets captured earlier (setup traffic, ARP
    # resolution, DHCP) are outside the observation and are classified as such on stderr, never
    # counted as a pass and never blamed on a claim that did not exist yet (the D-02 lesson).
    window_start = states[0][0]
    before_window = 0

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        stamp, _, packet = line.partition(" ")
        try:
            when = float(stamp)
        except ValueError:
            # A line we cannot read is not evidence of safety.
            findings.append("unparseable capture line: %s" % line)
            continue

        if when < window_start:
            before_window += 1
            continue

        state = None
        for recorded, text in states:
            if recorded <= when:
                state = (recorded, text)
            else:
                break

        if state is None:
            # Cannot happen once the window has opened, but never let it pass silently.
            findings.append("unattributed crossing at %.6f: %s" % (when, packet))
        elif protected(state[1]):
            findings.append(
                "crossed while reporting: %s (packet at %.6f, state recorded at %.6f): %s"
                % (state[1].strip(), when, state[0], packet)
            )

    if before_window:
        sys.stderr.write(
            "watch-oracle: %d packet(s) before the observation window were classified as "
            "outside it and not judged\n" % before_window
        )

    for finding in findings:
        print(finding)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
