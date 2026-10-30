// Seam: the extension accepting a secret request only from the genuine root broker.
// Attackers here run as the user, so these run without the broker installed.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { sign } from "../protocol.ts";
import { createRequestServer } from "../socket.ts";
import { BROKER_INTERPRETER, PROTOCOL_VERSION, validateSecretRequest } from "../secret.ts";

const broker = fileURLToPath(new URL("../broker/pi-secret-broker", import.meta.url));

function request(fields) {
	return sign("k", {
		type: "secret_request",
		id: "1",
		pid: process.pid,
		version: PROTOCOL_VERSION,
		argv: ["/bin/cat"],
		label: "x",
		ticket: "a".repeat(64),
		ts: Date.now(),
		...fields,
	});
}

const validate = (message, options = {}) =>
	validateSecretRequest(message, { expectedVersion: PROTOCOL_VERSION, usedTickets: new Set(), ...options });

test("refuses a broker whose protocol version differs, asking to reinstall", () => {
	const reason = validate(request({ version: PROTOCOL_VERSION + 1 }));
	assert.match(reason, /version/);
	assert.match(reason, /reinstall/i);
});

test("refuses a direct call to the socket, without broker", () => {
	assert.match(validate(request({})), /root/);
	// Claiming to be a root process (pid 1) is not enough: its cmdline is not the broker's.
	assert.match(validate(request({ pid: 1 })), /broker/);
});

test("refuses a fake broker that does not run as root", async () => {
	// The attacker's copy of the broker, with the root check removed, run by the user.
	const dir = mkdtempSync(join(tmpdir(), "pi-fake-broker-"));
	try {
		const fake = join(dir, "pi-secret-broker");
		const source = readFileSync(broker, "utf8")
			.replace(/^TICKET_DIR = .*$/m, `TICKET_DIR = ${JSON.stringify(join(dir, "tickets"))}`)
			.replace("if os.geteuid() != 0 or os.getuid() != 0:", "if False:")
			.replace("if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0", "if not stat.S_ISDIR(info.st_mode)");
		writeFileSync(fake, source, { mode: 0o700 });
		const socketPath = join(dir, "s.sock");
		const reasons = [];
		const server = createRequestServer({
			secret: () => "k",
			handlers: {
				secret_request(message, reply) {
					const reason = validate(message);
					reasons.push(reason);
					reply(reason ? { type: "secret_denied", id: message.id, reason } : { type: "secret_response", id: message.id, secret: "S" });
				},
			},
		});
		await new Promise((resolve) => server.listen(socketPath, resolve));
		const marker = join(dir, "consumer-ran");
		const result = await new Promise((resolve) => {
			const child = spawn(BROKER_INTERPRETER, ["-I", fake, "--label", "x", "--", "/usr/bin/touch", marker], {
				env: { PI_ASKPASS_SOCKET: socketPath, PI_ASKPASS_SECRET: "k", SUDO_UID: String(process.getuid()), SUDO_GID: String(process.getgid()) },
			});
			let stderr = "";
			child.stderr.on("data", (chunk) => (stderr += chunk));
			child.on("exit", (status) => resolve({ status, stderr }));
		});
		server.close();
		assert.equal(reasons.length, 1, result.stderr);
		assert.match(reasons[0], /root/);
		assert.notEqual(result.status, 0);
		assert.equal(existsSync(marker), false, "consumer ran for a fake broker");
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("refuses stale and malformed requests", () => {
	assert.match(validate(request({ ts: Date.now() - 10 * 60_000 })), /stale/);
	assert.match(validate(request({ argv: [] })), /malformed/);
	assert.match(validate(request({ argv: "cat" })), /malformed/);
	assert.match(validate(request({ ticket: "../../etc/passwd" })), /malformed/);
});
