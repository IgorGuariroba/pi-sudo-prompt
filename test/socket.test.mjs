// Seam: the extension's private socket server (socket.ts) and the modal queue.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { sign, verify } from "../protocol.ts";
import { createRequestServer, ModalQueue } from "../socket.ts";

const secret = "test-secret";
let dir;
before(() => {
	dir = mkdtempSync(join(tmpdir(), "pi-socket-test-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

async function listen(handlers) {
	const socketPath = join(dir, `${Math.random().toString(36).slice(2)}.sock`);
	const server = createRequestServer({ secret: () => secret, handlers });
	await new Promise((resolve) => server.listen(socketPath, resolve));
	return { socketPath, close: () => server.close() };
}

function request(socketPath, line) {
	return new Promise((resolve, reject) => {
		const socket = connect(socketPath);
		let buffer = "";
		socket.setEncoding("utf8");
		socket.on("connect", () => socket.write(`${line}\n`));
		socket.on("data", (chunk) => (buffer += chunk));
		socket.on("error", reject);
		socket.on("close", () => resolve(buffer ? JSON.parse(buffer.split("\n")[0]) : undefined));
	});
}

test("dispatches each message to the handler of its type", async () => {
	const seen = [];
	const handler = (name) => (message, reply) => {
		seen.push([name, message.id]);
		reply({ type: `${name}_ok`, id: message.id });
	};
	const server = await listen({ alpha: handler("alpha"), beta: handler("beta") });
	try {
		const a = await request(server.socketPath, JSON.stringify(sign(secret, { type: "alpha", id: "1" })));
		const b = await request(server.socketPath, JSON.stringify(sign(secret, { type: "beta", id: "2" })));
		assert.deepEqual(seen, [
			["alpha", "1"],
			["beta", "2"],
		]);
		assert.equal(a.type, "alpha_ok");
		assert.equal(b.type, "beta_ok");
		assert.ok(verify(secret, a) && verify(secret, b));
	} finally {
		server.close();
	}
});

test("unknown message type is refused with a valid signature", async () => {
	let called = false;
	const server = await listen({ alpha: () => (called = true) });
	try {
		const answer = await request(server.socketPath, JSON.stringify(sign(secret, { type: "gamma", id: "7" })));
		assert.equal(called, false);
		assert.ok(verify(secret, answer), "refusal must be signed");
		assert.equal(answer.id, "7");
		assert.match(answer.type, /denied/);
		assert.match(answer.reason, /unknown/);
	} finally {
		server.close();
	}
});

test("bad signature is refused like before (password_denied) and never dispatched", async () => {
	let called = false;
	const server = await listen({ password_request: () => (called = true) });
	try {
		const forged = { ...sign("wrong", { type: "password_request", id: "9" }) };
		const answer = await request(server.socketPath, JSON.stringify(forged));
		assert.equal(called, false);
		assert.ok(verify(secret, answer));
		assert.deepEqual({ type: answer.type, id: answer.id, reason: answer.reason }, {
			type: "password_denied",
			id: "9",
			reason: "bad signature",
		});
	} finally {
		server.close();
	}
});

test("malformed line closes the connection without an answer", async () => {
	const server = await listen({});
	try {
		assert.equal(await request(server.socketPath, "not json"), undefined);
	} finally {
		server.close();
	}
});

test("modal queue shows requests from different origins one at a time, in order", async () => {
	const queue = new ModalQueue();
	const events = [];
	let open = 0;
	const modal = (name, ms) => async () => {
		open++;
		assert.equal(open, 1, "only one modal open at a time");
		events.push(`open ${name}`);
		await new Promise((resolve) => setTimeout(resolve, ms));
		events.push(`close ${name}`);
		open--;
		return name;
	};
	const results = await Promise.all([
		queue.run(modal("sudo", 20)),
		queue.run(modal("secret", 5)),
		queue.run(modal("sudo-2", 1)),
	]);
	assert.deepEqual(results, ["sudo", "secret", "sudo-2"]);
	assert.deepEqual(events, ["open sudo", "close sudo", "open secret", "close secret", "open sudo-2", "close sudo-2"]);
});

test("a failing modal does not block the next one", async () => {
	const queue = new ModalQueue();
	await assert.rejects(queue.run(async () => {
		throw new Error("boom");
	}));
	assert.equal(await queue.run(async () => "next"), "next");
});
