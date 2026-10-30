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

# Start with no approved consumers. Never overwrite an administrator's existing file
# (including a symlink). Publish with ln, which also refuses a destination created meanwhile.
install -d -o root -g root -m 0755 "$(dirname "$ALLOWLIST")"
if [ ! -e "$ALLOWLIST" ] && [ ! -L "$ALLOWLIST" ]; then
    tmp=$(mktemp "$(dirname "$ALLOWLIST")/.allowlist.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    cat >"$tmp" <<'EOF'
# pi-sudo-prompt allowlist: no consumer is approved by default.
# Edit with: sudoedit /etc/pi-sudo-prompt/allowlist
# Each line: absolute REAL executable path, followed by whitespace-separated arguments.
# <name> matches exactly one nonempty argument, never an option beginning with '-'.
# Examples (uncomment only after reviewing the executable and its argument format):
# /usr/bin/keepassxc-cli show -q -t <db> <entrada>
# /usr/bin/gh auth login --with-token
# /usr/bin/docker login --password-stdin <registry>
EOF
    chown root:root "$tmp"
    chmod 0644 "$tmp"
    ln "$tmp" "$ALLOWLIST" || fail "allowlist already exists; refusing to overwrite it"
    rm -f "$tmp"
    trap - EXIT
fi

printf 'pi-secret-broker installed at %s (sudoers rule %s).\n' "$BROKER" "$SUDOERS"
