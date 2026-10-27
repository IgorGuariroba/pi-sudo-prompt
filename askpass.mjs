// SUDO_ASKPASS helper. Executed by sudo (through the launcher) with the prompt as argv[2].
// Asks the pi session over its private socket for the password and prints it to stdout,
// which must be sudo's private pipe. Exits 1 on any failure or denial.
//
// Self-contained on purpose: the extension side is loaded by pi's jiti, which caches native
// .mjs/.js modules for the whole process, so a module shared with index.ts would go stale
// after `/reload` (new index.ts + old shared module). This helper always runs in a fresh
// process. test/interop.test.mjs keeps it in lockstep with protocol.ts.

import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { fstatSync, readFileSync, readlinkSync } from "node:fs";
import { connect } from "node:net";
import { pathToFileURL } from "node:url";

export const ENV_SOCKET = "PI_ASKPASS_SOCKET";
export const ENV_SECRET = "PI_ASKPASS_SECRET";

function canonical(message) {
	const { signature: _ignored, ...rest } = message;
	return JSON.stringify(Object.keys(rest).sort().map((key) => [key, rest[key]]));
}

export function sign(secret, message) {
	return { ...message, signature: createHmac("sha256", secret).update(canonical(message)).digest("hex") };
}

export function verify(secret, message) {
	if (!message || typeof message.signature !== "string") return false;
	const expected = Buffer.from(createHmac("sha256", secret).update(canonical(message)).digest("hex"));
	const actual = Buffer.from(message.signature);
	return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** sudo/doas running setuid-root for this user: real uid = user, effective uid = 0. */
export function isPrivilegedSudo(pid, userUid) {
	try {
		const comm = readFileSync(`/proc/${pid}/comm`, "utf8").trim();
		const uid = readFileSync(`/proc/${pid}/status`, "utf8").match(/^Uid:\s+(\d+)\s+(\d+)/m);
		return (comm === "sudo" || comm === "doas") && !!uid && Number(uid[1]) === userUid && Number(uid[2]) === 0;
	} catch {
		return false;
	}
}

/** fd is the anonymous pipe sudo created as root (FIFO, uid 0, mode 0600). */
export function isSudoPipe(fd) {
	try {
		const stat = fstatSync(fd);
		return (
			stat.isFIFO() &&
			readlinkSync(`/proc/self/fd/${fd}`).startsWith("pipe:") &&
			stat.uid === 0 &&
			(stat.mode & 0o077) === 0
		);
	} catch {
		return false;
	}
}

function fail(reason) {
	process.stderr.write(`pi-askpass: ${reason}\n`);
	process.exit(1);
}

function main() {
	const socketPath = process.env[ENV_SOCKET];
	const secret = process.env[ENV_SECRET];
	if (!socketPath || !secret) fail("not running inside a pi session with sudo-prompt");
	if (!isPrivilegedSudo(process.ppid, process.getuid())) {
		fail("refusing: parent process is not sudo/doas running as root");
	}
	if (!isSudoPipe(1)) fail("refusing: stdout is not sudo's private pipe (possible hijacked SUDO_ASKPASS)");

	const id = randomUUID();
	const request = sign(secret, {
		type: "password_request",
		id,
		pid: process.pid,
		ppid: process.ppid,
		prompt: process.argv[2] ?? "Password:",
		ts: Date.now(),
	});

	const socket = connect(socketPath);
	let buffer = "";
	let settled = false;
	socket.setEncoding("utf8");
	socket.on("connect", () => socket.write(`${JSON.stringify(request)}\n`));
	socket.on("data", (chunk) => {
		buffer += chunk;
		const newline = buffer.indexOf("\n");
		if (newline === -1) return;
		settled = true;
		let message;
		try {
			message = JSON.parse(buffer.slice(0, newline));
		} catch {
			fail("malformed response");
		}
		socket.destroy();
		if (!verify(secret, message) || message.id !== id) fail("invalid response signature");
		if (message.type === "password_response" && typeof message.password === "string") {
			if (!isSudoPipe(1)) fail("refusing: stdout changed while waiting");
			process.stdout.write(`${message.password}\n`, () => process.exit(0));
			return;
		}
		fail(message.reason ?? "authentication cancelled");
	});
	socket.on("error", (error) => fail(`socket error: ${error.message}`));
	socket.on("close", () => {
		if (!settled) fail("pi closed the connection");
	});
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
