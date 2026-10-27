// Shared by the extension (index.ts) and the askpass helper (askpass.mjs).
// Wire format: one JSON object per line over a private Unix socket.
//   helper -> pi : { type: "password_request", id, pid, ppid, prompt, ts, signature }
//   pi -> helper : { type: "password_response", id, password, signature }
//               | { type: "password_denied",   id, reason,   signature }
// signature = HMAC-SHA256(secret, canonical JSON of every other field).

import { createHmac, timingSafeEqual } from "node:crypto";
import { fstatSync, readFileSync, readlinkSync, realpathSync, statSync } from "node:fs";

export const ENV_SOCKET = "PI_ASKPASS_SOCKET";
export const ENV_SECRET = "PI_ASKPASS_SECRET";
export const MAX_SKEW_MS = 30_000;

/**
 * Forces askpass mode (`sudo -A`) like Cursor's `alias sudo='sudo -A'`, but as a function
 * so it can step aside when the command already uses -S/--stdin (which conflicts with -A)
 * or -A itself. Without a TTY, SUDO_ASKPASS alone already makes sudo use the helper; -A
 * covers commands that do have a TTY (script, unbuffer, …).
 */
export const SUDO_FUNCTION =
	'sudo() { local a s=0; for a in "$@"; do if ((s)); then s=0; continue; fi; ' +
	'case "$a" in --) break;; --stdin|--askpass) command sudo "$@"; return;; --*) ;; ' +
	'-*[SA]*) command sudo "$@"; return;; -*[ughpCDRTU]) s=1;; -*) ;; *) break;; esac; done; ' +
	'command sudo -A "$@"; }';

function canonical(message) {
	const { signature: _ignored, ...rest } = message;
	return JSON.stringify(Object.keys(rest).sort().map((key) => [key, rest[key]]));
}

export function sign(secret, message) {
	const signature = createHmac("sha256", secret).update(canonical(message)).digest("hex");
	return { ...message, signature };
}

export function verify(secret, message) {
	if (!message || typeof message.signature !== "string") return false;
	const expected = Buffer.from(createHmac("sha256", secret).update(canonical(message)).digest("hex"));
	const actual = Buffer.from(message.signature);
	return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/** Process info from /proc. Returns undefined when the process is gone or unreadable. */
export function procInfo(pid) {
	try {
		const status = readFileSync(`/proc/${pid}/status`, "utf8");
		const comm = readFileSync(`/proc/${pid}/comm`, "utf8").trim();
		const uid = status.match(/^Uid:\s+(\d+)\s+(\d+)/m);
		const ppid = status.match(/^PPid:\s+(\d+)/m);
		if (!uid || !ppid) return undefined;
		return { comm, realUid: Number(uid[1]), effectiveUid: Number(uid[2]), ppid: Number(ppid[1]) };
	} catch {
		return undefined;
	}
}

/**
 * A genuine askpass parent is sudo/doas running setuid-root on behalf of this user:
 * real uid = caller, effective uid = 0. An unprivileged process cannot fake euid 0.
 */
export function isPrivilegedSudo(pid, userUid) {
	const info = procInfo(pid);
	return !!info && (info.comm === "sudo" || info.comm === "doas") && info.effectiveUid === 0 && info.realUid === userUid;
}

/**
 * True when `target` (an fd number or a /proc/<pid>/fd/<n> path) is the anonymous pipe sudo
 * created for the askpass helper: a FIFO owned by root with mode 0600. Anything a same-uid
 * attacker can set up (file, named fifo, process-substitution pipe) is owned by the user, and
 * a root-owned 0600 pipe cannot be reopened by the user through /proc. This is what stops a
 * hijacked SUDO_ASKPASS from doing `exec <helper> > somewhere-readable`, which keeps the PID
 * (so the parent is still sudo) but steals the password.
 */
export function isSudoPipe(target) {
	try {
		const stat = typeof target === "number" ? fstatSync(target) : statSync(target);
		const link = readlinkSync(typeof target === "number" ? `/proc/self/fd/${target}` : target);
		return stat.isFIFO() && link.startsWith("pipe:") && stat.uid === 0 && (stat.mode & 0o077) === 0;
	} catch {
		return false;
	}
}

export function readCmdline(pid) {
	try {
		return readFileSync(`/proc/${pid}/cmdline`, "utf8").replace(/\0$/, "").split("\0");
	} catch {
		return [];
	}
}

/** The only environment the helper may run with (everything else, e.g. NODE_OPTIONS, is code injection). */
export const HELPER_PATH = "/usr/bin:/bin";
export function helperEnvironment({ socketPath, secret }) {
	return { PATH: HELPER_PATH, [ENV_SOCKET]: socketPath, [ENV_SECRET]: secret };
}

/**
 * Launcher written to SUDO_ASKPASS. `env -i` drops whatever the agent's shell exported
 * (NODE_OPTIONS, LD_PRELOAD, ...) so the helper starts with exactly helperEnvironment().
 */
export function launcherScript({ nodePath, helperScript, socketPath, secret }) {
	const q = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;
	const env = Object.entries(helperEnvironment({ socketPath, secret }))
		.map(([key, value]) => q(`${key}=${value}`))
		.join(" ");
	return `#!/bin/sh\nexec /usr/bin/env -i ${env} ${q(nodePath)} ${q(helperScript)} "$@"\n`;
}

function readEnviron(pid) {
	try {
		const entries = readFileSync(`/proc/${pid}/environ`, "utf8").split("\0").filter(Boolean);
		return Object.fromEntries(entries.map((entry) => [entry.slice(0, entry.indexOf("=")), entry.slice(entry.indexOf("=") + 1)]));
	} catch {
		return undefined;
	}
}

function sameFile(a, b) {
	try {
		return realpathSync(a) === realpathSync(b);
	} catch {
		return false;
	}
}

/**
 * Server-side check of the process asking for the password. Returns undefined when it is the
 * genuine askpass helper, otherwise the reason to deny.
 */
export function validateRequester({ helperPid, sudoPid, helperScript, nodePath, socketPath, secret, uid }) {
	const helper = procInfo(helperPid);
	if (!helper || helper.ppid !== sudoPid) return "requester is not a child of sudo";
	if (!isPrivilegedSudo(sudoPid, uid)) return "parent is not sudo";

	// Exactly `node askpass.mjs <prompt>`: no interpreter flags such as --import/--require.
	const argv = readCmdline(helperPid);
	if (argv.length !== 3 || argv[1] !== helperScript) return "requester is not the askpass helper";
	if (!sameFile(`/proc/${helperPid}/exe`, nodePath)) return "unexpected interpreter";

	// Exactly the launcher's environment: blocks NODE_OPTIONS, LD_PRELOAD and friends.
	const env = readEnviron(helperPid);
	const expected = helperEnvironment({ socketPath, secret });
	if (!env || Object.keys(env).length !== Object.keys(expected).length) return "unexpected helper environment";
	for (const [key, value] of Object.entries(expected)) {
		if (env[key] !== value) return "unexpected helper environment";
	}

	// Password must go to sudo's private pipe, not somewhere the agent can read.
	if (!isSudoPipe(`/proc/${helperPid}/fd/1`)) return "helper stdout is not sudo's pipe";
	return undefined;
}
