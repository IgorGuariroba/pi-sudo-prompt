// askpass.mjs is self-contained (see its header): keep it in lockstep with protocol.ts.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as helper from "../askpass.mjs";
import * as pi from "../protocol.ts";

test("helper and pi agree on env names", () => {
	assert.equal(helper.ENV_SOCKET, pi.ENV_SOCKET);
	assert.equal(helper.ENV_SECRET, pi.ENV_SECRET);
});

test("what one side signs, the other verifies (both directions)", () => {
	const request = { type: "password_request", id: "1", pid: 10, ppid: 9, prompt: "[sudo] senha: ", ts: 1 };
	assert.ok(pi.verify("k", helper.sign("k", request)));
	assert.ok(helper.verify("k", pi.sign("k", { type: "password_response", id: "1", password: "x" })));
	assert.ok(!pi.verify("other", helper.sign("k", request)));
	assert.deepEqual(helper.sign("k", request), pi.sign("k", request));
});

test("helper and pi agree on what a privileged sudo is", () => {
	assert.equal(helper.isPrivilegedSudo(process.pid, process.getuid()), pi.isPrivilegedSudo(process.pid, process.getuid()));
});

test("helper and pi agree that a regular file/pipe is not sudo's pipe", () => {
	assert.equal(helper.isSudoPipe(0), pi.isSudoPipe("/proc/self/fd/0"));
	assert.equal(pi.isSudoPipe("/proc/self/fd/0"), false);
});

// Regression: pi's jiti re-evaluates .ts on /reload but keeps native .mjs/.js cached for the
// whole process. A relative non-.ts import from the extension side mixes new and stale code
// (seen as "launcherScript is not a function" after /reload).
test("extension side only imports relative .ts modules", () => {
	for (const file of ["index.ts", "modal.ts", "protocol.ts", "secret.ts", "socket.ts", "install.ts"]) {
		const source = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
		for (const [, specifier] of source.matchAll(/from\s+["'](\.[^"']+)["']/g)) {
			assert.match(specifier, /\.ts$/, `${file} imports ${specifier}; only .ts is reloaded by /reload`);
		}
	}
});

// Regression: protocol.ts was missing from package.json "files" (npm install would break).
test("every relative import of a shipped file is shipped too", () => {
	const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
	const shipped = new Set(pkg.files);
	for (const entry of pkg.pi.extensions) assert.ok(shipped.has(entry.replace(/^\.\//, "")), `${entry} not shipped`);
	for (const file of pkg.files.filter((f) => /\.(ts|mjs)$/.test(f))) {
		const source = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
		for (const [, specifier] of source.matchAll(/from\s+["']\.\/([^"']+)["']/g)) {
			assert.ok(shipped.has(specifier), `${file} imports ./${specifier}, missing from package.json "files"`);
		}
	}
});
