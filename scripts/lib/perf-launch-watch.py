#!/usr/bin/env python3
"""One APP-launch measurement: launch a command, timestamp every observable phase.

Usage:
  perf-launch-watch.py --mode direct|product --label NAME --app /usr/local/bin/gh-perf-app \
      [--timeout 60]

The application's first action is to print `date +%s.%N` on its standard output. The CLI
relays a session's output to its own stdout, and this process holds that pipe, so the
timestamp is read without touching the product or the sandboxed filesystem (the APP unit has
PrivateTmp, so a file written by the application is not visible to the host). Every other
milestone is observed from outside by scanning /proc, /run/netns and the helper state
directory, so no product code is instrumented or changed.

Output: one CSV line on stdout.

  label,mode,t0_epoch,self_epoch,exec_ms,netns_ms,relay_ms,launcher_ms,session_ms,app_ms,note
"""

import argparse
import os
import subprocess
import sys
import threading
import time

GHOST = ["runuser", "-u", "ghost", "-g", "ghostnector", "--"]


def processes_matching(needle):
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                cmdline = handle.read().replace(b"\x00", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if needle in cmdline:
            found.append(entry)
    return found


def app_processes(app):
    """The app itself: the shebang script, not the CLI or shell wrapper whose cmdline
    merely names it. `/bin/sh /usr/local/bin/gh-perf-app` is the exec'd script."""
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/cmdline", "rb") as handle:
                cmdline = handle.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            continue
        if cmdline.startswith("/bin/sh ") and app in cmdline:
            found.append(entry)
    return found


def netns_set():
    try:
        return set(os.listdir("/run/netns"))
    except OSError:
        return set()


def session_sockets():
    base = "/run/ghostnector/apps"
    found = set()
    try:
        for group in os.listdir(base):
            path = os.path.join(base, group, "stdio.sock")
            if os.path.exists(path):
                found.add(path)
    except OSError:
        pass
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=["direct", "product"])
    parser.add_argument("--label", required=True)
    parser.add_argument("--app", default="/usr/local/bin/gh-perf-app")
    parser.add_argument("--timeout", type=float, default=45.0)
    args = parser.parse_args()

    netns_before = netns_set()
    sessions_before = session_sockets()
    relays_before = set(processes_matching("ghostnector-appd-relay"))
    launchers_before = set(processes_matching("ghostnector-appd-launch"))

    if args.mode == "direct":
        command = GHOST + ["/bin/bash", "-c", f"exec {args.app}"]
    else:
        command = GHOST + ["/usr/bin/ghostnector", "run", args.app]

    t0 = time.time()
    t0_mono = time.monotonic()
    child = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    lines = []

    def read_output():
        try:
            for line in child.stdout:
                lines.append(line.decode("utf-8", "replace").strip())
        except Exception:  # noqa: BLE001
            pass

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()

    milestones = {"netns": None, "relay": None, "launcher": None, "session": None, "app": None}
    self_epoch = None
    deadline = t0_mono + args.timeout
    while time.monotonic() < deadline:
        if milestones["netns"] is None:
            current = netns_set() - netns_before
            if current:
                milestones["netns"] = time.monotonic()
        if milestones["relay"] is None:
            current = set(processes_matching("ghostnector-appd-relay")) - relays_before
            if current:
                milestones["relay"] = time.monotonic()
        if milestones["launcher"] is None:
            current = set(processes_matching("ghostnector-appd-launch")) - launchers_before
            if current:
                milestones["launcher"] = time.monotonic()
        if milestones["session"] is None:
            current = session_sockets() - sessions_before
            if current:
                milestones["session"] = time.monotonic()
        if milestones["app"] is None:
            if app_processes(args.app):
                milestones["app"] = time.monotonic()
        if self_epoch is None:
            for line in lines:
                try:
                    self_epoch = float(line)
                    break
                except ValueError:
                    continue
        if milestones["app"] is not None and self_epoch is not None:
            break
        time.sleep(0.005)

    def ms(key):
        value = milestones[key]
        return f"{(value - t0_mono) * 1000.0:.1f}" if value is not None else ""

    exec_ms = f"{(self_epoch - t0) * 1000.0:.1f}" if self_epoch is not None else ""
    note = ""
    if self_epoch is None:
        note = "no stdout timestamp"
        if child.poll() is not None:
            note = f"child exited {child.returncode} before the app printed"

    print(
        ",".join(
            [
                args.label,
                args.mode,
                f"{t0:.3f}",
                f"{self_epoch:.3f}" if self_epoch is not None else "",
                exec_ms,
                ms("netns"),
                ms("relay"),
                ms("launcher"),
                ms("session"),
                ms("app"),
                note,
            ]
        )
    )

    # Leave no session or app behind for the next measurement.
    try:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
    except Exception:  # noqa: BLE001
        pass


if __name__ == "__main__":
    sys.exit(main())
