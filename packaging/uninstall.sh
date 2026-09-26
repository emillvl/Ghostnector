#!/usr/bin/env bash
#
# Remove an installation made by packaging/install.sh. Run as root.
#
#   sudo packaging/uninstall.sh
#
# It refuses to run while a policy is applied: the documented way out is
# `ghostnector disconnect`, and silently deleting the kernel policy here would be exactly the
# "reset networking" behaviour the design forbids.

set -euo pipefail

fail() {
    echo "uninstall: $*" >&2
    exit 1
}

[ "$(id -u)" = "0" ] || fail "run this as root (sudo packaging/uninstall.sh)"

if command -v nft >/dev/null 2>&1 && nft list table inet ghostnector >/dev/null 2>&1; then
    fail "a Ghostnector policy is still applied; run 'ghostnector disconnect' first, or use the documented recovery path in docs/RECOVERY.md"
fi

systemctl disable --now ghostnector-core.service ghostnector-netd.service ghostnector-appd.service \
    ghostnector-bootguard.service >/dev/null 2>&1 || true

rm -f /usr/libexec/ghostnector-core /usr/libexec/ghostnector-netd /usr/libexec/ghostnector-appd \
    /usr/libexec/ghostnector-appd-launch /usr/libexec/ghostnector-appd-probe \
    /usr/libexec/ghostnector-dns /usr/libexec/ghostnector-bootguard
rm -f /usr/bin/ghostnector /usr/bin/ghostnector-gui
rm -f /usr/lib/systemd/system/ghostnector-core.service \
    /usr/lib/systemd/system/ghostnector-netd.service \
    /usr/lib/systemd/system/ghostnector-appd.service \
    /usr/lib/systemd/system/ghostnector-bootguard.service \
    /usr/lib/systemd/system/ghostnector-tor.service \
    /usr/lib/systemd/system/ghostnector-i2pd.service
rm -f /usr/lib/sysusers.d/ghostnector.conf /usr/lib/tmpfiles.d/ghostnector.conf
rm -f /usr/share/applications/ghostnector.desktop
rm -f /usr/share/icons/hicolor/scalable/apps/ghostnector.svg
rm -rf /var/lib/ghostnector /run/ghostnector

systemctl daemon-reload
systemctl reset-failed ghostnector-core.service ghostnector-netd.service ghostnector-appd.service \
    ghostnector-bootguard.service >/dev/null 2>&1 || true

echo "Ghostnector removed. The 'ghostnector' and 'ghostnector-netd' system users were left in place;"
echo "delete them with 'userdel ghostnector' / 'userdel ghostnector-netd' if you are sure."
