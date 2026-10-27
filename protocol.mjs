// Shared by the extension (index.ts) and the askpass helper (askpass.mjs).
// Wire format: one JSON object per line over a private Unix socket.
//   helper -> pi : { type: "password_request", id, pid, ppid, prompt, ts, signature }
//   pi -> helper : { type: "password_response", id, password, signature }
//               | { type: "password_denied",   id, reason,   signature }
// signature = HMAC-SHA256(secret, canonical JSON of every other field).

import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";

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

export function readCmdline(pid) {
	try {
		return readFileSync(`/proc/${pid}/cmdline`, "utf8").split("\0").filter(Boolean);
	} catch {
		return [];
	}
}
