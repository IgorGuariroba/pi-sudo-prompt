// pi side of the askpass protocol (the helper side lives in askpass.mjs).
// Wire format: one JSON object per line over a private Unix socket.
//   helper -> pi : { type: "password_request", id, pid, ppid, prompt, ts, signature }
//   pi -> helper : { type: "password_response", id, password, signature }
//               | { type: "password_denied",   id, reason,   signature }
// signature = HMAC-SHA256(secret, canonical JSON of every other field).
//
// Must stay a .ts module: pi's jiti re-evaluates .ts on `/reload` but keeps native
// .mjs/.js modules cached for the whole process (see docs/adr/0001-askpass-socket.md).

import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, readlinkSync, realpathSync, statSync } from "node:fs";

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

export type Message = Record<string, unknown> & { signature?: string };

export function canonical(message: Message): string {
	const { signature: _ignored, ...rest } = message;
	return JSON.stringify(
		Object.keys(rest)
			.sort()
			.map((key) => [key, rest[key]]),
	);
}

export function sign<T extends Message>(secret: string, message: T): T & { signature: string } {
	return { ...message, signature: createHmac("sha256", secret).update(canonical(message)).digest("hex") };
}

export function verify(secret: string, message: unknown): boolean {
	if (!message || typeof (message as Message).signature !== "string") return false;
	const expected = Buffer.from(
		createHmac("sha256", secret)
			.update(canonical(message as Message))
			.digest("hex"),
	);
	const actual = Buffer.from((message as Message).signature as string);
	return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export interface ProcInfo {
	comm: string;
	realUid: number;
	effectiveUid: number;
	ppid: number;
}

/** Process info from /proc. Returns undefined when the process is gone or unreadable. */
export function procInfo(pid: number): ProcInfo | undefined {
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
export function isPrivilegedSudo(pid: number, userUid: number): boolean {
	const info = procInfo(pid);
	return !!info && (info.comm === "sudo" || info.comm === "doas") && info.effectiveUid === 0 && info.realUid === userUid;
}

/**
 * True when `fdPath` (/proc/<pid>/fd/<n>) is the anonymous pipe sudo created for the askpass
 * helper: a FIFO owned by root with mode 0600. Anything a same-uid attacker can set up (file,
 * named fifo, process-substitution pipe) is owned by the user, and a root-owned 0600 pipe
 * cannot be reopened by the user through /proc. This stops a hijacked SUDO_ASKPASS from doing
 * `exec <helper> > somewhere-readable`, which keeps the PID (parent is still sudo) but steals
 * the password.
 */
export function isSudoPipe(fdPath: string): boolean {
	try {
		const stat = statSync(fdPath);
		return (
			stat.isFIFO() && readlinkSync(fdPath).startsWith("pipe:") && stat.uid === 0 && (stat.mode & 0o077) === 0
		);
	} catch {
		return false;
	}
}

export function readCmdline(pid: number): string[] {
	try {
		return readFileSync(`/proc/${pid}/cmdline`, "utf8").replace(/\0$/, "").split("\0");
	} catch {
		return [];
	}
}

/** The only environment the helper may run with (anything else, e.g. NODE_OPTIONS, is code injection). */
export const HELPER_PATH = "/usr/bin:/bin";

export function helperEnvironment({ socketPath, secret }: { socketPath: string; secret: string }) {
	return { PATH: HELPER_PATH, [ENV_SOCKET]: socketPath, [ENV_SECRET]: secret };
}

export function shellQuote(value: string): string {
	return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * Launcher written to SUDO_ASKPASS. `env -i` drops whatever the agent's shell exported
 * (NODE_OPTIONS, LD_PRELOAD, ...) so the helper starts with exactly helperEnvironment().
 */
export function launcherScript(options: {
	nodePath: string;
	helperScript: string;
	socketPath: string;
	secret: string;
}): string {
	const env = Object.entries(helperEnvironment(options))
		.map(([key, value]) => shellQuote(`${key}=${value}`))
		.join(" ");
	return `#!/bin/sh\nexec /usr/bin/env -i ${env} ${shellQuote(options.nodePath)} ${shellQuote(options.helperScript)} "$@"\n`;
}

function readEnviron(pid: number): Record<string, string> | undefined {
	try {
		const entries = readFileSync(`/proc/${pid}/environ`, "utf8").split("\0").filter(Boolean);
		return Object.fromEntries(entries.map((entry) => [entry.slice(0, entry.indexOf("=")), entry.slice(entry.indexOf("=") + 1)]));
	} catch {
		return undefined;
	}
}

function sameFile(a: string, b: string): boolean {
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
export function validateRequester(options: {
	helperPid: number;
	sudoPid: number;
	helperScript: string;
	nodePath: string;
	socketPath: string;
	secret: string;
	uid: number;
}): string | undefined {
	const { helperPid, sudoPid, helperScript, nodePath, uid } = options;
	const helper = procInfo(helperPid);
	if (!helper || helper.ppid !== sudoPid) return "requester is not a child of sudo";
	if (!isPrivilegedSudo(sudoPid, uid)) return "parent is not sudo";

	// Exactly `node askpass.mjs <prompt>`: no interpreter flags such as --import/--require.
	const argv = readCmdline(helperPid);
	if (argv.length !== 3 || argv[1] !== helperScript) return "requester is not the askpass helper";
	if (!sameFile(`/proc/${helperPid}/exe`, nodePath)) return "unexpected interpreter";

	// Exactly the launcher's environment: blocks NODE_OPTIONS, LD_PRELOAD and friends.
	const env = readEnviron(helperPid);
	const expected = helperEnvironment(options);
	if (!env || Object.keys(env).length !== Object.keys(expected).length) return "unexpected helper environment";
	for (const [key, value] of Object.entries(expected)) {
		if (env[key] !== value) return "unexpected helper environment";
	}

	// Password must go to sudo's private pipe, not somewhere the agent can read.
	if (!isSudoPipe(`/proc/${helperPid}/fd/1`)) return "helper stdout is not sudo's pipe";
	return undefined;
}

/** Title of the sudo modal; the secret request modal must never reuse it (ADR 0002). */
export const SUDO_MODAL_TITLE = "Sudo Authentication Required";
