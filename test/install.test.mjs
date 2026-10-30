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
