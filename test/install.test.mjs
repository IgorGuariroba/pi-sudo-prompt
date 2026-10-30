// Manual installer of the root broker (broker/install.sh). Installing needs root, so here we
// only check what can be checked as a user: it is valid sh, refuses without root, installs the
// broker where the extension expects it and validates sudoers with visudo before enabling it.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { BROKER_PATH } from "../secret.ts";

const installer = fileURLToPath(new URL("../broker/install.sh", import.meta.url));
const source = readFileSync(installer, "utf8");

const isolatedRoot = spawnSync("unshare", ["-Ur", "-m", "sh", "-c", "mount -t tmpfs tmpfs /etc && mount -t tmpfs tmpfs /usr/local"], { encoding: "utf8" });

test("installer creates a root-owned empty allowlist, preserves edits and updates the broker", {
	skip: isolatedRoot.status !== 0 ? "user/mount namespaces unavailable; requires isolated root filesystem" : false,
}, () => {
	const result = spawnSync("unshare", ["-Ur", "-m", "sh", "-eu", "-c", `
		mount -t tmpfs tmpfs /etc
		mount -t tmpfs tmpfs /usr/local
		printf 'root:x:0:0:root:/root:/bin/sh\\n' > /etc/passwd
		printf 'root:x:0:\\n' > /etc/group
		mkdir -p /etc/sudoers.d
		printf 'root ALL=(ALL) ALL\\n' > /etc/sudoers
		chmod 0440 /etc/sudoers
		sh "$1"
		test "$(stat -c '%u:%g:%a' /usr/local/libexec/pi-sudo-prompt/pi-secret-broker)" = '0:0:755'
		test "$(stat -c '%u:%g:%a' /etc/sudoers.d/pi-sudo-prompt)" = '0:0:440'
		test "$(stat -c '%u:%g:%a' /etc/pi-sudo-prompt/allowlist)" = '0:0:644'
		! grep -vE '^([[:space:]]*#.*|[[:space:]]*)$' /etc/pi-sudo-prompt/allowlist
		grep -q 'keepassxc-cli show -q -t' /etc/pi-sudo-prompt/allowlist
		printf '/my/consumer --safe\\n' > /etc/pi-sudo-prompt/allowlist
		printf '# outdated broker\\n' > /usr/local/libexec/pi-sudo-prompt/pi-secret-broker
		sh "$1"
		cmp "$(dirname "$1")/pi-secret-broker" /usr/local/libexec/pi-sudo-prompt/pi-secret-broker
		test "$(cat /etc/pi-sudo-prompt/allowlist)" = '/my/consumer --safe'
		visudo -c
	`, "installer-test", installer], { encoding: "utf8", timeout: 10000 });
	assert.equal(result.status, 0, result.stderr + result.stdout);
});

test("installer is valid sh", () => {
	const result = spawnSync("sh", ["-n", installer], { encoding: "utf8" });
	assert.equal(result.status, 0, result.stderr);
});

test("installer refuses to run without root and changes nothing", { skip: process.getuid() === 0 }, () => {
	const result = spawnSync("sh", [installer], { encoding: "utf8" });
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /root/);
});

test("installs the broker root-owned at the path the extension checks", () => {
	assert.ok(source.includes(BROKER_PATH));
	assert.match(source, /install\s+-o root -g root -m 0755/);
});

test("sudoers rule is NOPASSWD for the broker only and is validated with visudo -c", () => {
	assert.match(source, /NOPASSWD: \$BROKER\b/);
	assert.match(source, /visudo -c -f/);
	assert.match(source, /env_keep \+= "PI_ASKPASS_SOCKET PI_ASKPASS_SECRET"/);
	assert.doesNotMatch(source, /NOPASSWD: ALL/);
});
