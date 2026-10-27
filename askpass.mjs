// SUDO_ASKPASS helper. Executed by sudo with the prompt as argv[2].
// Asks the pi session (over its private socket) for the password and prints it
// to stdout, which is a pipe read by sudo. Exits 1 on any failure or denial.

import { randomUUID } from "node:crypto";
import { connect } from "node:net";
import { ENV_SECRET, ENV_SOCKET, isPrivilegedSudo, sign, verify } from "./protocol.mjs";

function fail(reason) {
	process.stderr.write(`pi-askpass: ${reason}\n`);
	process.exit(1);
}

const socketPath = process.env[ENV_SOCKET];
const secret = process.env[ENV_SECRET];
if (!socketPath || !secret) fail("not running inside a pi session with sudo-prompt");

const uid = process.getuid();
if (!isPrivilegedSudo(process.ppid, uid)) fail("refusing: parent process is not sudo/doas running as root");

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
	buffer = "";
	socket.destroy();
	if (!verify(secret, message) || message.id !== id) fail("invalid response signature");
	if (message.type === "password_response" && typeof message.password === "string") {
		process.stdout.write(`${message.password}\n`, () => process.exit(0));
		return;
	}
	fail(message.reason ?? "authentication cancelled");
});
socket.on("error", (error) => fail(`socket error: ${error.message}`));
socket.on("close", () => {
	if (!settled) fail("pi closed the connection");
});
