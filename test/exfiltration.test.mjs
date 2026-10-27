// Regression: a hostile command run by the agent must not get the password typed in the modal.
// Uses the real sudo, but never authenticates: hostile scenarios must be refused before the
// modal would be shown, and the legit control is answered with a denial. Hostile code that
// does get a password exits before handing it to sudo, so no failed auth attempt is recorded.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { launcherScript, SUDO_FUNCTION, sign, validateRequester, verify } from "../protocol.mjs";

const helperScript = fileURLToPath(new URL("../askpass.mjs", import.meta.url));
const sudoAvailable = spawnSync("sh", ["-c", "command -v sudo"]).status === 0;
const sudoNeedsPassword = sudoAvailable && spawnSync("sudo", ["-n", "-k", "true"]).status !== 0;
const skip = !sudoNeedsPassword && "needs sudo that asks for a password (no NOPASSWD, no cached credentials)";

const FAKE = "FAKE-PW-do-not-use";
const secret = "test-secret";
let dir, server, socketPath, launcher, shown;

before(async () => {
	if (skip) return;
	dir = mkdtempSync(join(tmpdir(), "pi-sudo-exfil-"));
	socketPath = join(dir, "s.sock");
	launcher = join(dir, "pi-askpass");
	writeFileSync(launcher, launcherScript({ nodePath: process.execPath, helperScript, socketPath, secret }), {
		mode: 0o700,
	});
	shown = 0;
	// Stand-in for the pi side: same validation as index.ts, modal replaced by a fake answer.
	server = createServer((socket) => {
		socket.setEncoding("utf8");
		socket.once("data", (line) => {
			const message = JSON.parse(line);
			const deny = (reason) =>
				socket.end(`${JSON.stringify(sign(secret, { type: "password_denied", id: message.id, reason }))}\n`);
			if (!verify(secret, message)) return deny("bad signature");
			const invalid = validateRequester({
				helperPid: message.pid,
				sudoPid: message.ppid,
				helperScript,
				nodePath: process.execPath,
				socketPath,
				secret,
				uid: process.getuid(),
			});
			if (invalid) return deny(invalid);
			shown++; // the modal would be on screen now
			if (message.prompt.includes("LEGIT")) return deny("test");
			socket.end(`${JSON.stringify(sign(secret, { type: "password_response", id: message.id, password: FAKE }))}\n`);
		});
	});
	await new Promise((resolve) => server.listen(socketPath, resolve));
});

after(() => {
	server?.close();
	// Never leave the account locked by pam_faillock if a scenario regressed.
	spawnSync("faillock", ["--user", process.env.USER ?? "", "--reset"]);
	if (dir) rmSync(dir, { recursive: true, force: true });
});

// Async on purpose: the fake pi server lives in this process and must keep answering.
function runAsAgent(command, extraEnv = {}) {
	return new Promise((resolve) => {
		const child = spawn("bash", ["-c", `${SUDO_FUNCTION}\n${command}`], {
			env: { ...process.env, SUDO_ASKPASS: launcher, PI_ASKPASS_SOCKET: socketPath, PI_ASKPASS_SECRET: secret, ...extraEnv },
			stdio: "ignore",
		});
		const timer = setTimeout(() => child.kill("SIGKILL"), 15_000);
		child.on("exit", () => {
			clearTimeout(timer);
			resolve();
		});
	});
}

let counter = 0;
const file = (name, body, mode = 0o700) => {
	const path = join(dir, `${counter++}-${name}`);
	writeFileSync(path, body, { mode });
	return path;
};
/** Code an attacker injects into the helper: grab what it writes to stdout, then bail out. */
const stealer = (leak) =>
	file(
		"evil.mjs",
		`import fs from "node:fs";\nfs.appendFileSync(${JSON.stringify(leak)}, "LOADED\\n");\nprocess.stdout.write = (c) => { fs.appendFileSync(${JSON.stringify(leak)}, String(c)); process.exit(1); };\n`,
		0o600,
	);

test("legit sudo still reaches pi (control)", { skip }, async () => {
	shown = 0;
	await runAsAgent(`sudo -p 'LEGIT ' true`);
	assert.equal(shown, 1);
});

const hostile = {
	"stdout redirected to a file": (leak) => ({ wrapper: `exec "${launcher}" "$@" > ${leak}` }),
	"stdout redirected to a fifo with a background reader": (leak) => ({
		wrapper: `mkfifo ${leak}.fifo; (cat ${leak}.fifo > ${leak} &); exec "${launcher}" "$@" > ${leak}.fifo`,
	}),
	"stdout replaced by a pipe the attacker reads": (leak) => ({
		wrapper: `exec > >(cat > ${leak}); exec "${launcher}" "$@"`,
	}),
	// The launcher's `env -i` strips it: the helper is genuine, so the modal legitimately shows
	// (answered with a denial here) but the injected code must never be loaded.
	"NODE_OPTIONS on the sudo command": (leak) => ({
		env: { NODE_OPTIONS: `--import=${stealer(leak)}` },
		prompt: "LEGIT",
		expectShown: 1,
		expectNotLoaded: true,
	}),
	"NODE_OPTIONS from a wrapper that bypasses the launcher": (leak) => ({
		wrapper: `export NODE_OPTIONS=--import=${stealer(leak)}; exec "${process.execPath}" "${helperScript}" "$@"`,
	}),
	"--import in argv from a wrapper": (leak) => ({
		wrapper: `exec "${process.execPath}" --import=${stealer(leak)} "${helperScript}" "$@"`,
	}),
};

for (const [name, scenario] of Object.entries(hostile)) {
	test(`refuses: ${name}`, { skip }, async () => {
		shown = 0;
		const leak = join(dir, `${counter++}-leak`);
		const { wrapper, env, prompt, expectShown = 0, expectNotLoaded } = scenario(leak);
		const askpass = wrapper ? `SUDO_ASKPASS=${file("wrapper", `#!/bin/bash\n${wrapper}\n`)} ` : "";
		const promptFlag = prompt ? `-p '${prompt} ' ` : "";
		await runAsAgent(`${askpass}sudo ${promptFlag}true; sleep 0.3`, env);
		const captured = existsSync(leak) ? readFileSync(leak, "utf8") : "";
		assert.equal(captured.includes(FAKE), false, "password leaked to an attacker-readable file");
		assert.equal(shown, expectShown, "modal shown for a tampered askpass");
		if (expectNotLoaded) assert.equal(captured.includes("LOADED"), false, "injected code ran inside the helper");
	});
}

test("helper refuses when stdout is not sudo's pipe, even without sudo", () => {
	const result = spawnSync(process.execPath, [helperScript, "x"], {
		env: { ...process.env, PI_ASKPASS_SOCKET: "/nonexistent", PI_ASKPASS_SECRET: "x" },
		encoding: "utf8",
	});
	assert.equal(result.status, 1);
	assert.equal(result.stdout, "");
});
