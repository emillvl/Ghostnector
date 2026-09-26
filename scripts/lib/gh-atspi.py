#!/usr/bin/env python3
"""Read and drive the Ghostnector window through AT-SPI.

Subcommands:
  labels                 print every visible label text, one per line
  banner                 print the label that carries the state wording
  click NAME             activate the first widget named NAME (button, check box, menu item)
  actions NAME           print the roles and action names for every node named NAME
  coords NAME            print the centre of the first named node with real screen extents
  state NAME             print checked/unchecked for a check box
  wait NAME SECONDS      wait until a widget named NAME exists
  has NAME               exit 0 if a widget named NAME exists

The window must be running on the same session bus as this process (DBUS_SESSION_BUS_ADDRESS).
Everything here is presentation-layer only; the control plane stays the authority.
"""
import sys
import time

import pyatspi

APP_NAME = "ghostnector-gui"


def app():
    desktop = pyatspi.Registry.getDesktop(0)
    for candidate in desktop:
        if (candidate.name or "") == APP_NAME:
            return candidate
    return None


def walk(node):
    yield node
    try:
        for child in node:
            yield from walk(child)
    except Exception:
        return


def find_all(name, role=None, contains=False):
    root = app()
    if root is None:
        return []
    matches = []
    for node in walk(root):
        try:
            text = (node.name or "").strip()
            matched = name.lower() in text.lower() if contains else text == name
            if matched and (role is None or node.getRoleName() == role):
                matches.append(node)
        except Exception:
            continue
    return matches


def find(name, role=None, contains=False):
    matches = find_all(name, role, contains)
    return matches[0] if matches else None


def action_names(node):
    try:
        action = node.queryAction()
        return [action.getName(index) for index in range(action.nActions)]
    except Exception:
        return []


def click(name, role=None):
    candidates = find_all(name, role)
    if not candidates:
        print(f"not found: {name!r}")
        return 1
    preferred = ("click", "toggle", "activate", "press", "check", "select")
    for node in candidates:
        names = action_names(node)
        for index, label in enumerate(names):
            if label in preferred:
                node.queryAction().doAction(index)
                print(f"clicked {name!r} ({node.getRoleName()}) via {label}")
                return 0
    # A non-label node with any action may still be the control (for example a switch that exposes
    # a single unnamed action). A label's actions are clipboard operations, never a control, so it
    # is never activated by the fallback.
    for node in candidates:
        if node.getRoleName() == "label":
            continue
        names = action_names(node)
        if names:
            node.queryAction().doAction(0)
            print(f"clicked {name!r} ({node.getRoleName()}) via action 0 ({names[0]})")
            return 0
    print(f"no action on any non-label node named {name!r}")
    return 1


def labels():
    out = []
    root = app()
    if root is None:
        return out
    for node in walk(root):
        try:
            if node.getRoleName() == "label":
                text = (node.name or "").strip()
                if text:
                    out.append(text)
        except Exception:
            pass
    return out


def checked(name):
    node = find(name)
    if node is None:
        print("missing")
        return 1
    try:
        states = node.getState().getStates()
        print("checked" if pyatspi.STATE_CHECKED in states else "unchecked")
        return 0
    except Exception as error:
        print(f"unknown: {error}")
        return 1


def coords(name, constant=None):
    """Print the centre of the first named node that has real screen extents.

    Non-label nodes come first: clicking a switch's text label does nothing, while clicking the
    switch itself (or a check button's indicator) toggles it.
    """
    candidates = find_all(name)
    if not candidates:
        print(f"not found: {name!r}")
        return 1
    ordered = [node for node in candidates if node.getRoleName() != "label"]
    ordered += [node for node in candidates if node.getRoleName() == "label"]
    for node in ordered:
        try:
            extents = node.queryComponent().getExtents(constant or pyatspi.DESKTOP_COORDS)
            if extents.width > 0 and extents.height > 0:
                print(f"{extents.x + extents.width // 2} {extents.y + extents.height // 2}")
                return 0
        except Exception:
            continue
    print(f"no screen extents for {name!r}")
    return 1


def focused(name):
    """Exit 0 when a node named NAME currently has keyboard focus."""
    for node in find_all(name):
        try:
            if pyatspi.STATE_FOCUSED in node.getState().getStates():
                return 0
        except Exception:
            continue
    return 1


def focus_report():
    root = app()
    if root is None:
        return 1
    found = 0
    for node in walk(root):
        try:
            if pyatspi.STATE_FOCUSED in node.getState().getStates():
                print(f"{node.getRoleName()}: {(node.name or '').strip()!r}")
                found += 1
        except Exception:
            continue
    if not found:
        print("(nothing focused)")
    return 0


def enabled(name):
    """Print enabled/disabled for the first node named NAME."""
    for node in find_all(name):
        try:
            states = node.getState().getStates()
            if pyatspi.STATE_SENSITIVE in states and pyatspi.STATE_ENABLED in states:
                print("enabled")
            else:
                print("disabled")
            return 0
        except Exception:
            continue
    print("missing")
    return 1


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    command = sys.argv[1]
    if command == "labels":
        for text in labels():
            print(text)
        return 0
    if command == "banner":
        state_words = ("off ", "protected", "blocked", "applying", "unknown", "denied")
        for text in labels():
            lowered = text.lower()
            if lowered.startswith(state_words):
                print(text)
                return 0
        print("(no banner found)")
        return 1
    if command == "click":
        return click(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    if command == "actions":
        for node in find_all(sys.argv[2]):
            print(f"{node.getRoleName()}: {action_names(node)}")
        return 0
    if command == "state":
        return checked(sys.argv[2])
    if command == "coords":
        return coords(sys.argv[2])
    if command == "coords-screen":
        return coords(sys.argv[2], pyatspi.SCREEN_COORDS)
    if command == "focused":
        return focused(sys.argv[2])
    if command == "focus-report":
        return focus_report()
    if command == "enabled":
        return enabled(sys.argv[2])
    if command == "has":
        return 0 if find(sys.argv[2], contains=True) else 1
    if command == "wait":
        name = sys.argv[2]
        seconds = int(sys.argv[3])
        for _ in range(seconds * 5):
            if find(name, contains=True):
                print(f"present: {name}")
                return 0
            time.sleep(0.2)
        print(f"timeout: {name}")
        return 1
    print(f"unknown command {command}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
