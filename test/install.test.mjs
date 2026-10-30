// Manual installer of the root broker (broker/install.sh). Installing needs root, so here we
// only check what can be checked as a user: it is valid sh, refuses without root, installs the
// broker where the extension expects it and validates sudoers with visudo before enabling it.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifySecretRequest } from "../allowlist.ts";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { BROKER_PATH } from "../secret.ts";

const installer = fileURLToPath(new URL("../broker/install.sh", import.meta.url));
const source = readFileSync(installer, "utf8");

test("instala allowlist vazia com exemplos comentados e preserva configuração existente", () => {
	// Sandbox only: root ownership and system paths are replaced, never invoking sudo.
	const dir = mkdtempSync(join(tmpdir(), "pi-install-"));
	try {
		const bin = join(dir, "bin");
		mkdirSync(bin);
		mkdirSync(join(dir, "sudoers.d"));
		for (const [command, script] of Object.entries({ id: "echo 0", visudo: "exit 0", chown: "exit 0" })) {
			writeFileSync(join(bin, command), `#!/bin/sh\n${script}\n`, { mode: 0o755 });
		}
		writeFileSync(join(dir, "pi-secret-broker"), "#!/usr/bin/python3\n");
		const sandbox = source.replaceAll("/usr/local/libexec/pi-sudo-prompt", `${dir}/libexec`)
			.replaceAll("/etc/sudoers.d", `${dir}/sudoers.d`)
			.replaceAll("/etc/pi-sudo-prompt", `${dir}/config`)
			.replaceAll("-o root -g root ", "");
		const script = join(dir, "install.sh");
		writeFileSync(script, sandbox);
		const run = () => {
			const result = spawnSync("sh", [script], { encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}` } });
			assert.equal(result.status, 0, result.stderr);
		};
		run();
		const file = join(dir, "config", "allowlist");
		const initial = readFileSync(file, "utf8");
		assert.match(initial, /#.*\/usr\/bin\/keepassxc-cli show -q -t <db> <entrada>/);
		assert.ok(initial.split("\n").every((line) => !line.trim() || line.trim().startsWith("#")));
		assert.equal(classifySecretRequest(["/usr/bin/keepassxc-cli", "show", "-q", "-t", "db", "npm"], initial), "unverified");
		writeFileSync(file, "/usr/bin/keepassxc-cli show -q -t <db> <entrada>\n");
		chmodSync(file, 0o640);
		run();
		assert.equal(readFileSync(file, "utf8"), "/usr/bin/keepassxc-cli show -q -t <db> <entrada>\n");
	} finally { rmSync(dir, { recursive: true, force: true }); }
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
