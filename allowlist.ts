// Pure classification (seam 2) and trusted file boundary. No pi imports (ADR 0001).
import { closeSync, constants, fstatSync, openSync, readFileSync, realpathSync, lstatSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";

export type SecretClassification = "allowed" | "unverified";
export const ALLOWLIST_PATH = "/etc/pi-sudo-prompt/allowlist";

/** Resolve only argv[0]; arguments are data and must remain byte-for-byte unchanged. */
export function resolveConsumerArgv(argv: readonly string[]): string[] {
	return [realpathSync(argv[0]), ...argv.slice(1)];
}

/** Fail closed on unsafe metadata, links, missing files or read errors. Check the opened inode. */
export function readTrustedAllowlist(path = ALLOWLIST_PATH): string {
	let fd: number | undefined;
	try {
		if (!isAbsolute(path)) return "";
		for (let parent = dirname(path); ; parent = dirname(parent)) {
			const info = lstatSync(parent);
			if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0) return "";
			if (parent === "/") break;
		}
		fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
		const info = fstatSync(fd);
		if (!info.isFile() || info.uid !== 0 || (info.mode & 0o022) !== 0) return "";
		return readFileSync(fd, "utf8");
	} catch {
		return "";
	} finally {
		if (fd !== undefined) closeSync(fd);
	}
}

/** Whitespace-separated argv patterns; <name> matches exactly one non-option argument. */
export function classifySecretRequest(argv: readonly string[], text: string): SecretClassification {
	for (const line of text.split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;
		const pattern = trimmed.split(/\s+/);
		if (!isAbsolute(pattern[0]) || pattern.length !== argv.length || pattern[0] !== argv[0]) continue;
		if (pattern.slice(1).every((part, index) => {
			const arg = argv[index + 1];
			return /^<[\p{L}\p{N}_-]+>$/u.test(part) ? arg.length > 0 && !arg.startsWith("-") : part === arg;
		})) return "allowed";
	}
	return "unverified";
}
