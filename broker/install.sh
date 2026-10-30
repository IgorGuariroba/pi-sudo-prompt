#!/bin/sh
# Manual installer of the pi-sudo-prompt root broker (docs/adr/0002-broker-root-para-segredos-duraveis.md).
# Read it before running. Usage, from the package directory:
#
#     sudo sh broker/install.sh
#
# Installs:
#   $BROKER                          root:root 0755 (run by /usr/bin/python3 -I)
#   /etc/sudoers.d/pi-sudo-prompt    root:root 0440, validated with visudo -c before use
# Running it again updates the broker to the version of this package.
set -eu

BROKER=/usr/local/libexec/pi-sudo-prompt/pi-secret-broker
SUDOERS=/etc/sudoers.d/pi-sudo-prompt
ALLOWLIST=/etc/pi-sudo-prompt/allowlist
SOURCE=$(dirname "$0")/pi-secret-broker

fail() { printf 'install: %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "must run as root: sudo sh $0"
[ "$(uname -s)" = Linux ] || fail "only Linux is supported"
[ -x /usr/bin/python3 ] || fail "/usr/bin/python3 is required (the broker uses only its standard library)"
[ -f "$SOURCE" ] || fail "broker source not found: $SOURCE"
command -v visudo >/dev/null 2>&1 || fail "visudo not found"

# The extension refuses the broker unless it and every directory above it are root-owned
# and not writable by group/others.
install -d -o root -g root -m 0755 "$(dirname "$BROKER")"
install -o root -g root -m 0755 "$SOURCE" "$BROKER.new"
mv -f "$BROKER.new" "$BROKER"

tmp=$(mktemp /etc/sudoers.d/.pi-sudo-prompt.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<EOF
# pi-sudo-prompt: lets pi-secret-run start the root broker without a password (ADR 0002).
# The broker runs the consumer as the calling user, never as root.
Defaults!$BROKER env_keep += "PI_ASKPASS_SOCKET PI_ASKPASS_SECRET"
ALL ALL=(root) NOPASSWD: $BROKER
EOF
chown root:root "$tmp"
chmod 0440 "$tmp"
visudo -c -f "$tmp" >/dev/null || fail "generated sudoers rule is invalid; nothing enabled"
mv -f "$tmp" "$SUDOERS"
trap - EXIT
visudo -c >/dev/null || fail "sudoers is invalid after the change; remove $SUDOERS"

# Empty by default: examples are comments, never implicit approvals.
# noclobber also protects an existing allowlist during concurrent installations.
install -d -o root -g root -m 0755 "$(dirname "$ALLOWLIST")"
if [ ! -e "$ALLOWLIST" ] && [ ! -L "$ALLOWLIST" ]; then
	(set -C; umask 022; cat >"$ALLOWLIST" <<'EOF'
# pi-sudo-prompt allowlist: absolute executable + argument format.
# Nothing is approved by default. Edit with sudoedit /etc/pi-sudo-prompt/allowlist.
# Example (adjust the executable path before uncommenting):
# /usr/bin/keepassxc-cli show -q -t <db> <entrada>
EOF
	) || fail "could not create initial allowlist (existing files are never overwritten)"
	chown root:root "$ALLOWLIST"
	chmod 0644 "$ALLOWLIST"
fi

printf 'pi-secret-broker installed at %s (sudoers rule %s).\n' "$BROKER" "$SUDOERS"
