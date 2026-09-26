#!/usr/bin/env python3
"""Read and drive the Ghostnector window through AT-SPI.

Subcommands:
  labels                 print every visible label text, one per line
  banner                 print the label that carries the state wording
  click NAME             activate the first widget named NAME (button, check box, menu item)
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


def find(name, role=None, contains=False):
    root = app()
    if root is None:
        return None
    for node in walk(root):
        try:
            text = (node.name or "").strip()
            matched = name.lower() in text.lower() if contains else text == name
            if matched and (role is None or node.getRoleName() == role):
                return node
        except Exception:
            continue
    return None


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


def click(name, role=None):
    node = find(name, role)
    if node is None:
        print(f"not found: {name!r}")
        return 1
    try:
        action = node.queryAction()
        for index in range(action.nActions):
            label = action.getName(index)
            if label in ("click", "toggle", "activate", "press"):
                action.doAction(index)
                print(f"clicked {name!r} via {label}")
                return 0
        action.doAction(0)
        print(f"clicked {name!r} via action 0")
        return 0
    except Exception as error:
        print(f"cannot click {name!r}: {error}")
        return 1


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
    if command == "state":
        return checked(sys.argv[2])
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
