// Regression (#11): pi >= 1.4 ships as a Bun-compiled single binary, so the extension's
// process.execPath is `pi`, not `node`. A launcher running `pi askpass.mjs <prompt>` started
// pi itself instead of the helper: no modal, and sudo saw failed attempts until timeout.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { helperEnvironment, helperRuntime, launcherScript } from "../protocol.ts";

const helperScript = fileURLToPath(new URL("../askpass.mjs", import.meta.url));

/** A Bun-compiled executable to stand in for pi: PI_SUDO_PROMPT_TEST_BUN_EXE, or `pi` on PATH. */
function findBunCompiledExe() {
	const candidate =
		process.env.PI_SUDO_PROMPT_TEST_BUN_EXE ??
		spawnSync("sh", ["-c", "command -v pi"], { encoding: "utf8" }).stdout.trim();
	if (!candidate) return undefined;
	const probe = spawnSync("/usr/bin/env", ["-i", "BUN_BE_BUN=1", candidate, "-e", "console.log(typeof Bun)"], {
		encoding: "utf8",
		timeout: 5000,
	});
	return probe.stdout.trim() === "object" ? candidate : undefined;
}

test("helperRuntime: node needs no extra environment", () => {
	const runtime = helperRuntime({ execPath: "/usr/bin/node", versions: { node: "22.0.0" } });
	assert.deepEqual(runtime, { nodePath: "/usr/bin/node", runtimeEnv: {} });
});

test("helperRuntime: a Bun executable must be told to behave as bun (BUN_BE_BUN)", () => {
	const runtime = helperRuntime({ execPath: "/opt/pi/pi", versions: { node: "24.3.0", bun: "1.4.4" } });
	assert.deepEqual(runtime, { nodePath: "/opt/pi/pi", runtimeEnv: { BUN_BE_BUN: "1" } });
});

test("helperEnvironment includes the runtime environment (validated server-side)", () => {
	const env = helperEnvironment({ socketPath: "/s", secret: "k", runtimeEnv: { BUN_BE_BUN: "1" } });
	assert.equal(env.BUN_BE_BUN, "1");
	assert.equal(env.PATH, "/usr/bin:/bin");
});

const bunExe = findBunCompiledExe();
test(
	"launcher on a Bun-compiled pi actually runs askpass.mjs",
	{ skip: !bunExe && "no Bun-compiled executable (set PI_SUDO_PROMPT_TEST_BUN_EXE)" },
	() => {
		const dir = mkdtempSync(join(tmpdir(), "pi-sudo-runtime-"));
		try {
			const launcher = join(dir, "pi-askpass");
			const runtime = helperRuntime({ execPath: bunExe, versions: { bun: "x" } });
			writeFileSync(
				launcher,
				launcherScript({ ...runtime, helperScript, socketPath: join(dir, "s.sock"), secret: "k" }),
				{ mode: 0o700 },
			);
			const result = spawnSync(launcher, ["[sudo] senha:"], { encoding: "utf8", timeout: 10_000, input: "" });
			assert.equal(result.error, undefined, "launcher hung: the helper never ran");
			// Outside sudo the genuine helper refuses right away: proof that askpass.mjs ran.
			assert.equal(result.status, 1);
			assert.match(result.stderr, /pi-askpass: refusing: parent process is not sudo/);
			assert.equal(result.stdout, "", "nothing may reach sudo's password pipe");
		} finally {
			rmSync(dir, { recursive: true, force: true });
		}
	},
);
