import assert from "node:assert/strict";
import { test } from "node:test";
import { installationHint, registerInstallCommand } from "../install.ts";
import { secretRunScript, validateSecretRequest } from "../secret.ts";
import { spawnSync } from "node:child_process";

test("missing and mismatched broker refusals suggest the user command and manual installer", () => {
	const hint = installationHint("/pkg/broker/install.sh");
	const missing = spawnSync("sh", ["-c", secretRunScript({ brokerPath: "/missing-broker-issue-7", installHint: hint }) + "\n", "pi-secret-run", "--label", "x", "--", "true"], {
		env: { ...process.env, PI_ASKPASS_SOCKET: "/unused", PI_ASKPASS_SECRET: "x" }, encoding: "utf8",
	});
	assert.notEqual(missing.status, 0);
	const mismatch = validateSecretRequest({ ts: Date.now(), version: -1 }, { expectedVersion: 1, usedTickets: new Set(), reinstallHint: hint });
	for (const message of [missing.stderr, mismatch]) {
		assert.match(message, /\/sudo-prompt install-broker/);
		assert.match(message, /sudo sh '\/pkg\/broker\/install.sh'/);
	}
});

function harness(run = async () => ({ exitCode: 0 })) {
	let command;
	const notices = [];
	registerInstallCommand({ registerCommand(name, options) {
		assert.equal(name, "sudo-prompt");
		command = options;
	} }, { installer: "/package with spaces/broker/install.sh", run });
	return { invoke: (args, mode = "tui") => command.handler(args, {
		mode, cwd: "/work", ui: { notify: (...notice) => notices.push(notice) },
	}), notices };
}

test("user command runs only the packaged installer through sudo, with no argument injection", async () => {
	const calls = [];
	const h = harness(async (...args) => { calls.push(args); return { exitCode: 0 }; });
	await h.invoke("install-broker; touch /tmp/not-allowed");
	await h.invoke("");
	assert.equal(calls.length, 0);
	await h.invoke("install-broker");
	await h.invoke(" install-broker ");
	assert.deepEqual(calls, [
		["sudo sh '/package with spaces/broker/install.sh'", "/work"],
		["sudo sh '/package with spaces/broker/install.sh'", "/work"],
	]);
	assert.match(h.notices.at(-1)[0], /instalado|atualizado/);
});

test("installation failure or cancellation is reported without exposing process output", async () => {
	for (const run of [async () => ({ exitCode: 1 }), async () => ({ exitCode: null }), async () => { throw new Error("sensitive output"); }]) {
		const h = harness(run);
		await h.invoke("install-broker");
		assert.equal(h.notices.at(-1)[1], "error");
		assert.doesNotMatch(JSON.stringify(h.notices), /sensitive output/);
	}
});

test("install-broker refuses outside the TUI without starting a process", async () => {
	const h = harness(() => assert.fail("must not execute outside TUI"));
	for (const mode of ["print", "json", "rpc"]) await h.invoke("install-broker", mode);
	assert.equal(h.notices.length, 3);
	for (const [message, level] of h.notices) {
		assert.match(message, /TUI/);
		assert.equal(level, "error");
	}
});
