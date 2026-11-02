// broker/pi-secret-broker (Python, runs as root) is self-contained: keep it in lockstep with
// the pi side (protocol.ts + secret.ts). Nothing here needs root.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { ENV_SECRET, ENV_SOCKET, sign } from "../protocol.ts";
import { BROKER_INTERPRETER, BROKER_PATH, PROTOCOL_VERSION, requestDigest, TICKET_DIR } from "../secret.ts";

const broker = fileURLToPath(new URL("../broker/pi-secret-broker", import.meta.url));
const brokerSource = readFileSync(broker, "utf8");

/** Calls a function of the broker module with JSON arguments; returns its JSON result. */
function python(fn, ...args) {
	const code = `import json, runpy, sys\nm = runpy.run_path(sys.argv[1], run_name="lib")\nprint(json.dumps(m[sys.argv[2]](*json.loads(sys.argv[3]))))`;
	const result = spawnSync(BROKER_INTERPRETER, ["-I", "-c", code, broker, fn, JSON.stringify(args)], { encoding: "utf8" });
	assert.equal(result.status, 0, result.stderr);
	return JSON.parse(result.stdout);
}

const constant = (name) => brokerSource.match(new RegExp(`^${name} = (.+)$`, "m"))?.[1];

test("broker and pi agree on protocol version, paths and env names", () => {
	assert.equal(Number(constant("PROTOCOL_VERSION")), PROTOCOL_VERSION);
	assert.equal(JSON.parse(constant("TICKET_DIR")), TICKET_DIR);
	assert.equal(JSON.parse(constant("ENV_SOCKET")), ENV_SOCKET);
	assert.equal(JSON.parse(constant("ENV_SECRET")), ENV_SECRET);
	assert.equal(brokerSource.split("\n")[0], `#!${BROKER_INTERPRETER} -I`);
	assert.ok(BROKER_PATH.startsWith("/usr/local/libexec/"));
});

test("what one side signs, the other verifies (same bytes, unicode and control chars)", () => {
	const request = {
		type: "secret_request",
		id: "abc",
		pid: 4242,
		version: PROTOCOL_VERSION,
		argv: ["/usr/bin/keepassxc-cli", "show", "-q", "-t", "cofre ção.kdbx", 'a"b\\c\n\t\u0001\u007f'],
		label: "senha mestra 🔑",
		ticket: "f".repeat(64),
		ts: 1720000000000,
	};
	assert.equal(python("sign", "k", request).signature, sign("k", request).signature);
	assert.ok(python("verify", "k", sign("k", { type: "secret_response", id: "abc", secret: "s3 ✓" })));
	assert.ok(!python("verify", "other", sign("k", { type: "secret_response", id: "abc", secret: "x" })));
	assert.equal(python("request_digest", request), requestDigest(sign("k", request)));
});

test("broker refuses to run when it is not root", () => {
	const result = spawnSync(BROKER_INTERPRETER, ["-I", broker, "--label", "x", "--", "/bin/true"], {
		env: { [ENV_SOCKET]: "/nonexistent", [ENV_SECRET]: "x", SUDO_UID: String(process.getuid()) },
		encoding: "utf8",
	});
	assert.notEqual(result.status, 0);
	assert.equal(result.stdout, "");
	assert.match(result.stderr, /root/);
});
