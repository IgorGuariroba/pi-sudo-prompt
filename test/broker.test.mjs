// Seam 1: pi-secret-run -> real root broker (installed by broker/install.sh) -> a socket server
// playing the pi side, with the same validation as index.ts and the modal replaced by a fake
// answer. Skipped when the broker is not installed.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { BROKER_PATH, PROTOCOL_VERSION, secretRunScript, validateSecretRequest } from "../secret.ts";
import { createRequestServer } from "../socket.ts";

const installed = existsSync(BROKER_PATH) && spawnSync("sudo", ["-n", "-l", "--", BROKER_PATH]).status === 0;
const skip = !installed && `needs the broker installed (sudo sh broker/install.sh); not found at ${BROKER_PATH}`;

const SECRET = `FAKE-secret-${randomBytes(6).toString("hex")}`;
const secret = "test-secret";
let dir, server, socketPath, launcher;
/** How the fake pi answers: "secret" (user typed it), "cancel", or a function (message, reply). */
let answer = "secret";
let expectedVersion = PROTOCOL_VERSION;
let shown = 0;
const usedTickets = new Set();

before(async () => {
	if (skip) return;
	dir = mkdtempSync(join(tmpdir(), "pi-broker-test-"));
	socketPath = join(dir, "s.sock");
	launcher = join(dir, "pi-secret-run");
	writeFileSync(launcher, secretRunScript({ installHint: "sudo sh broker/install.sh" }), { mode: 0o700 });
	server = createRequestServer({
		secret: () => secret,
		handlers: {
			secret_request(message, reply) {
				const reason = validateSecretRequest(message, { expectedVersion, usedTickets });
				if (reason) return reply({ type: "secret_denied", id: message.id, reason });
				shown++; // the modal would be on screen now
				if (typeof answer === "function") return answer(message, reply);
				if (answer === "cancel") return reply({ type: "secret_denied", id: message.id, reason: "secret request cancelled" });
				reply({ type: "secret_response", id: message.id, secret: SECRET });
			},
		},
	});
	await new Promise((resolve) => server.listen(socketPath, resolve));
});

after(() => {
	server?.close();
	if (dir) rmSync(dir, { recursive: true, force: true });
});

// Async on purpose: the fake pi server lives in this process and must keep answering.
function secretRun(args) {
	return new Promise((resolve) => {
		const child = spawn(launcher, ["--label", "test secret", "--", ...args], {
			env: { ...process.env, PI_ASKPASS_SOCKET: socketPath, PI_ASKPASS_SECRET: secret },
		});
		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => (stdout += chunk));
		child.stderr.on("data", (chunk) => (stderr += chunk));
		const timer = setTimeout(() => child.kill("SIGKILL"), 15_000);
		child.on("exit", (status) => {
			clearTimeout(timer);
			resolve({ status, stdout, stderr });
		});
	});
}

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** Runs a consumer that publishes its pid and waits, without reading its stdin yet. */
async function withWaitingConsumer(inspect) {
	const pidFile = join(dir, `${randomBytes(4).toString("hex")}.pid`);
	const run = secretRun(["/bin/sh", "-c", 'echo $$ > "$1"; sleep 2; cat > /dev/null', "sh", pidFile]);
	const deadline = Date.now() + 10_000;
	while (!existsSync(pidFile) || !readFileSync(pidFile, "utf8").trim()) {
		if (Date.now() > deadline) throw new Error("consumer never started");
		await new Promise((resolve) => setTimeout(resolve, 50));
	}
	try {
		inspect(Number(readFileSync(pidFile, "utf8")));
	} finally {
		const result = await run;
		assert.equal(result.status, 0, result.stderr);
	}
}

test("the consumer gets the secret on stdin and it does not show up in the output", { skip }, async () => {
	answer = "secret";
	const result = await secretRun(["/bin/sh", "-c", 'IFS= read -r s; printf %s "$s" | sha256sum']);
	assert.equal(result.status, 0, result.stderr);
	assert.equal(result.stdout.split(" ")[0], sha256(SECRET));
	assert.ok(!result.stdout.includes(SECRET) && !result.stderr.includes(SECRET));
});

test("no cache: every call opens the modal", { skip }, async () => {
	answer = "secret";
	const before = shown;
	await secretRun(["/bin/sh", "-c", "cat > /dev/null"]);
	await secretRun(["/bin/sh", "-c", "cat > /dev/null"]);
	assert.equal(shown - before, 2);
});

test("the agent cannot reopen the consumer's pipe through /proc/<pid>/fd", { skip }, async () => {
	answer = "secret";
	await withWaitingConsumer((pid) => {
		const fd0 = statSync(`/proc/${pid}/fd/0`);
		assert.ok(fd0.isFIFO());
		assert.equal(fd0.uid, 0, "pipe must be created by root");
		assert.equal(fd0.mode & 0o077, 0);
		assert.throws(() => openSync(`/proc/${pid}/fd/0`, "r"), /EACCES|EPERM/);
	});
});

test("the secret is not in the consumer's /proc/<pid>/environ", { skip }, async () => {
	answer = "secret";
	await withWaitingConsumer((pid) => {
		const environ = readFileSync(`/proc/${pid}/environ`, "utf8");
		assert.ok(environ.length > 0);
		assert.ok(!environ.includes(SECRET));
		assert.ok(!environ.includes("PI_ASKPASS_SECRET"));
	});
});

test("the consumer never runs as root: it gets the caller's uid and gid", { skip }, async () => {
	answer = "secret";
	const result = await secretRun(["/bin/sh", "-c", "cat > /dev/null; id -u; id -g; id -ru; id -rg"]);
	assert.equal(result.status, 0, result.stderr);
	const [uid, gid, ruid, rgid] = result.stdout.trim().split("\n").map(Number);
	assert.deepEqual([uid, gid, ruid, rgid], [process.getuid(), process.getgid(), process.getuid(), process.getgid()]);
	assert.notEqual(uid, 0);
});

test("a broker with a different protocol version is refused", { skip }, async () => {
	expectedVersion = PROTOCOL_VERSION + 1;
	const before = shown;
	try {
		const result = await secretRun(["/bin/sh", "-c", 'IFS= read -r s; echo "got:$s"']);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /version/);
		assert.ok(!result.stdout.includes("got:"));
		assert.equal(shown, before);
	} finally {
		expectedVersion = PROTOCOL_VERSION;
	}
});

test("cancelled modal: non-zero exit with the reason, consumer never runs", { skip }, async () => {
	answer = "cancel";
	try {
		const marker = join(dir, "ran");
		const result = await secretRun(["/usr/bin/touch", marker]);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /cancelled/);
		assert.equal(existsSync(marker), false);
	} finally {
		answer = "secret";
	}
});

test("a forged request reusing a running broker's pid is refused", { skip }, async () => {
	let forged;
	answer = (message, reply) => {
		// While the real broker waits for the modal, the agent sends its own request with the
		// broker's pid, argv and label, but it cannot know or create the broker's ticket.
		const { signature: _s, ...fields } = message;
		forged = [
			validateSecretRequest({ ...fields, ticket: randomBytes(32).toString("hex") }, { expectedVersion, usedTickets }),
			validateSecretRequest(fields, { expectedVersion, usedTickets }), // replay of the real one
		];
		reply({ type: "secret_denied", id: message.id, reason: "test" });
	};
	try {
		await secretRun(["/bin/sh", "-c", "cat > /dev/null"]);
		assert.ok(forged, "the broker never asked");
		for (const reason of forged) assert.match(reason, /not proven/);
	} finally {
		answer = "secret";
	}
});
