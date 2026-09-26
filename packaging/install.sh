#!/usr/bin/env bash
#
# Install Ghostnector from a cargo build directory. Run as root.
#
#   sudo packaging/install.sh [target-dir]
#
# `target-dir` defaults to ../target/release. It must contain the workspace binaries. Installing is
# deliberately explicit about what it does: files, system users/groups, tmpfiles, a daemon reload,
# and enabling the four system units. It never starts Tor or I2P: the control plane manages those.
#
# The GUI is installed for whoever is in the `ghostnector` group; the script prints the one command
# left for the administrator.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
target="${1:-$here/../target/release}"
libexec=/usr/libexec
bindir=/usr/bin

fail() {
    echo "install: $*" >&2
    exit 1
}

[ "$(id -u)" = "0" ] || fail "run this as root (sudo packaging/install.sh)"

for binary in ghostnector-core ghostnector-netd ghostnector-appd ghostnector-appd-launch \
    ghostnector-appd-probe ghostnector-dns ghostnector-bootguard ghostnector ghostnector-gui; do
    [ -f "$target/$binary" ] || fail "missing $target/$binary; build with 'cargo build --release --workspace --bins -p ghostnector-gui --features gtk'"
done

install -D -m 0755 "$target/ghostnector-core" "$libexec/ghostnector-core"
install -D -m 0755 "$target/ghostnector-netd" "$libexec/ghostnector-netd"
install -D -m 0755 "$target/ghostnector-appd" "$libexec/ghostnector-appd"
install -D -m 0755 "$target/ghostnector-appd-launch" "$libexec/ghostnector-appd-launch"
install -D -m 0755 "$target/ghostnector-appd-probe" "$libexec/ghostnector-appd-probe"
install -D -m 0755 "$target/ghostnector-dns" "$libexec/ghostnector-dns"
install -D -m 0755 "$target/ghostnector-bootguard" "$libexec/ghostnector-bootguard"
install -D -m 0755 "$target/ghostnector" "$bindir/ghostnector"
install -D -m 0755 "$target/ghostnector-gui" "$bindir/ghostnector-gui"

install -D -m 0644 "$here/systemd/ghostnector-core.service" /usr/lib/systemd/system/ghostnector-core.service
install -D -m 0644 "$here/systemd/ghostnector-netd.service" /usr/lib/systemd/system/ghostnector-netd.service
install -D -m 0644 "$here/systemd/ghostnector-appd.service" /usr/lib/systemd/system/ghostnector-appd.service
install -D -m 0644 "$here/systemd/ghostnector-bootguard.service" /usr/lib/systemd/system/ghostnector-bootguard.service
install -D -m 0644 "$here/systemd/ghostnector-tor.service" /usr/lib/systemd/system/ghostnector-tor.service
install -D -m 0644 "$here/systemd/ghostnector-i2pd.service" /usr/lib/systemd/system/ghostnector-i2pd.service
install -D -m 0644 "$here/sysusers.d/ghostnector.conf" /usr/lib/sysusers.d/ghostnector.conf
install -D -m 0644 "$here/tmpfiles.d/ghostnector.conf" /usr/lib/tmpfiles.d/ghostnector.conf
install -D -m 0644 "$here/polkit-1/rules.d/50-ghostnector.rules" \
    /usr/share/polkit-1/rules.d/50-ghostnector.rules
install -d -m 0755 /etc/ghostnector
install -m 0644 "$here/core.env.example" /etc/ghostnector/core.env.example

install -D -m 0644 "$here/desktop/ghostnector.desktop" /usr/share/applications/ghostnector.desktop
install -D -m 0644 "$here/icons/hicolor/scalable/apps/ghostnector.svg" \
    /usr/share/icons/hicolor/scalable/apps/ghostnector.svg
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t /usr/share/icons/hicolor 2>/dev/null || true
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q 2>/dev/null || true

systemd-sysusers
systemd-tmpfiles --create
systemctl daemon-reload
systemctl enable ghostnector-netd.service ghostnector-appd.service ghostnector-bootguard.service \
    ghostnector-core.service >/dev/null

echo "Ghostnector installed."
echo
echo "For the command line and the window, add yourself to the ghostnector group, then log back in:"
echo "    sudo usermod -aG ghostnector \$USER"
echo
echo "Start it now with:  sudo systemctl start ghostnector-core"
echo
echo "To let it claim 'protected and verified', configure check endpoints in /etc/ghostnector/core.env"
echo "(see /etc/ghostnector/core.env.example) and restart ghostnector-core. Until then it reports"
echo "'protected, but unverified' and says which checks are missing."
