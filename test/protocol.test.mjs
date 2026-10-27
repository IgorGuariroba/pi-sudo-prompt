import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { isPrivilegedSudo, sign, SUDO_FUNCTION, verify } from "../protocol.mjs";

const helper = fileURLToPath(new URL("../askpass.mjs", import.meta.url));

test("signed messages verify; tampering or wrong secret fails", () => {
	const message = sign("s3cret", { type: "password_request", id: "1", prompt: "[sudo] senha:", ts: 1 });
	assert.ok(verify("s3cret", message));
	assert.ok(!verify("other", message));
	assert.ok(!verify("s3cret", { ...message, prompt: "x" }));
	assert.ok(!verify("s3cret", { ...message, signature: undefined }));
});

test("this test process is not a privileged sudo", () => {
	assert.equal(isPrivilegedSudo(process.pid, process.getuid()), false);
});

test("helper refuses when its parent is not sudo", () => {
	const result = spawnSync(process.execPath, [helper, "[sudo] senha:"], {
		env: { ...process.env, PI_ASKPASS_SOCKET: "/nonexistent", PI_ASKPASS_SECRET: "x" },
		encoding: "utf8",
	});
	assert.equal(result.status, 1);
	assert.equal(result.stdout, "");
	assert.match(result.stderr, /parent process is not sudo/);
});

test("helper refuses outside a pi session", () => {
	const env = { ...process.env };
	delete env.PI_ASKPASS_SOCKET;
	delete env.PI_ASKPASS_SECRET;
	const result = spawnSync(process.execPath, [helper], { env, encoding: "utf8" });
	assert.equal(result.status, 1);
	assert.match(result.stderr, /not running inside a pi session/);
});

test("sudo() function adds -A except with -S/-A", () => {
	const dir = mkdtempSync(join(tmpdir(), "sudo-fn-"));
	try {
		const fake = join(dir, "sudo");
		writeFileSync(fake, '#!/bin/sh\necho "$*"\n');
		chmodSync(fake, 0o755);
		const run = (line) =>
			execFileSync("bash", ["-c", `${SUDO_FUNCTION}\n${line}`], {
				env: { ...process.env, PATH: `${dir}:${process.env.PATH}` },
				encoding: "utf8",
			}).trim();
		assert.equal(run("sudo apt update"), "-A apt update");
		assert.equal(run("sudo -u root whoami"), "-A -u root whoami");
		assert.equal(run("echo x | sudo -S true"), "-S true");
		assert.equal(run("sudo -kS true"), "-kS true");
		assert.equal(run("sudo --stdin true"), "--stdin true");
		assert.equal(run("sudo -A true"), "-A true");
		assert.equal(run("sudo -u Sam true"), "-A -u Sam true");
		assert.equal(run("sudo env FOO=-S true"), "-A env FOO=-S true");
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});
