#!/usr/bin/env python3
"""Describe or activate a GAction exported by the Ghostnector window.

Usage: gh-action.py ADDRESS describe ACTION
       gh-action.py ADDRESS activate ACTION

The address is the session bus address the window is running on. The connection is made
explicitly (not through DBUS_SESSION_BUS_ADDRESS) because the window's bus is started by the
qualification harness and a plain gdbus lookup can fail on it.
"""
import sys

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

DEST = "org.ghostnector.Gui"
PATH = "/org/ghostnector/Gui"


def connection(address):
    flags = (
        Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
        | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION
    )
    return Gio.DBusConnection.new_for_address_sync(address, flags, None, None)


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    address, command, action = sys.argv[1], sys.argv[2], sys.argv[3]
    conn = connection(address)
    if command == "describe":
        result = conn.call_sync(
            DEST,
            PATH,
            "org.gtk.Actions",
            "Describe",
            GLib.Variant("(s)", (action,)),
            None,
            Gio.DBusCallFlags.NONE,
            -1,
            None,
        )
        print(result.print_(True))
        return 0
    if command == "activate":
        conn.call_sync(
            DEST,
            PATH,
            "org.gtk.Actions",
            "Activate",
            GLib.Variant("(sava{sv})", (action, [], {})),
            None,
            Gio.DBusCallFlags.NONE,
            -1,
            None,
        )
        print(f"activated {action}")
        return 0
    print(f"unknown command {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
