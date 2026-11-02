// Seam: the `pi-secret-run` launcher the agent calls. These refusals need no root broker.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { secretRunScript } from "../secret.ts";

let dir;
before(() => {
	dir = mkdtempSync(join(tmpdir(), "pi-secret-run-test-"));
});
after(() => rmSync(dir, { recursive: true, force: true }));

let counter = 0;
function launcher(options) {
	const path = join(dir, `${counter++}-pi-secret-run`);
	writeFileSync(path, secretRunScript({ installHint: "sudo sh /pkg/broker/install.sh", ...options }), { mode: 0o700 });
	return path;
}

function run(path, args, env = {}) {
	return spawnSync(path, args, {
		env: { PATH: process.env.PATH, PI_ASKPASS_SOCKET: "/nonexistent.sock", PI_ASKPASS_SECRET: "x", ...env },
		encoding: "utf8",
	});
}

test("refuses outside an interactive pi session (no TUI)", () => {
	const result = run(launcher({ brokerPath: "/bin/true" }), ["--label", "x", "--", "true"], {
		PI_ASKPASS_SOCKET: "",
		PI_ASKPASS_SECRET: "",
	});
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /TUI/);
});

test("refuses when the broker is not installed and explains how to install it", () => {
	const result = run(launcher({ brokerPath: join(dir, "missing-broker") }), ["--label", "x", "--", "true"]);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /broker/);
	assert.match(result.stderr, /sudo sh \/pkg\/broker\/install\.sh/);
});

test("refuses on a system that is not Linux", () => {
	const fakeBin = mkdtempSync(join(dir, "bin-"));
	writeFileSync(join(fakeBin, "uname"), "#!/bin/sh\necho Darwin\n");
	chmodSync(join(fakeBin, "uname"), 0o755);
	const result = run(launcher({ brokerPath: "/bin/true" }), ["--label", "x", "--", "true"], {
		PATH: `${fakeBin}:${process.env.PATH}`,
	});
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /Linux/);
});

test("refuses a call without --label or without a command", () => {
	const path = launcher({ brokerPath: "/bin/true" });
	for (const args of [["--", "true"], ["--label", "x"], ["--label", "x", "--"], ["true"]]) {
		const result = run(path, args);
		assert.notEqual(result.status, 0, `accepted ${args.join(" ")}`);
		assert.match(result.stderr, /usage/i);
	}
});

test("refuses a consumer that is not an executable file", () => {
	const result = run(launcher({ brokerPath: "/bin/true" }), ["--label", "x", "--", "no-such-command-xyz"]);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /no-such-command-xyz/);
});

test("hands the broker the resolved absolute path of the consumer", () => {
	// Stand-in broker that just prints what it got (the real one is called through sudo).
	const broker = join(dir, "echo-broker");
	writeFileSync(broker, '#!/bin/sh\nprintf "%s\\n" "$@"\n', { mode: 0o755 });
	const fakeSudo = mkdtempSync(join(dir, "sudo-"));
	writeFileSync(join(fakeSudo, "sudo"), '#!/bin/sh\n[ "$2" = -l ] && exit 0\nwhile [ "$1" != "--" ]; do shift; done; shift; exec "$@"\n');
	chmodSync(join(fakeSudo, "sudo"), 0o755);
	const result = run(launcher({ brokerPath: broker }), ["--label", "my db", "--", "sh", "-c", "x"], {
		PATH: `${fakeSudo}:${process.env.PATH}`,
	});
	assert.equal(result.status, 0, result.stderr);
	const sh = spawnSync("sh", ["-c", "command -v sh"], { encoding: "utf8" }).stdout.trim();
	assert.deepEqual(result.stdout.trimEnd().split("\n"), ["--label", "my db", "--", sh, "-c", "x"]);
});
