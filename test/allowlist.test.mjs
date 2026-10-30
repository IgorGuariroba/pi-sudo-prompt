import assert from "node:assert/strict";
import { test } from "node:test";
import { mkdtempSync, symlinkSync, rmSync, writeFileSync, chmodSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { classifySecretRequest, resolveConsumerArgv, readTrustedAllowlist } from "../allowlist.ts";

test("resolve o executável para o caminho real antes da classificação", () => {
	const dir = mkdtempSync(join(tmpdir(), "pi-allowlist-"));
	try {
		const executable = join(dir, "consumer");
		const alias = join(dir, "alias");
		writeFileSync(executable, "", { mode: 0o755 });
		symlinkSync(executable, alias);
		const argv = resolveConsumerArgv([alias, "show", "um banco", "npm"]);
		assert.deepEqual(argv, [executable, "show", "um banco", "npm"]);
		assert.equal(classifySecretRequest(argv, `${executable} show <db> <entrada>`), "allowed");
		assert.equal(classifySecretRequest(argv, `${alias} show <db> <entrada>`), "unverified");
	} finally { rmSync(dir, { recursive: true, force: true }); }
});

test("leitura confiável ignora arquivo do usuário, escrita de grupo/outros, symlink e ausência", () => {
	const dir = mkdtempSync(join(tmpdir(), "pi-allowlist-"));
	try {
		const file = join(dir, "allowlist");
		writeFileSync(file, "/usr/bin/cat", { mode: 0o644 });
		assert.equal(readTrustedAllowlist(file), "");
		chmodSync(file, 0o666);
		assert.equal(readTrustedAllowlist(file), "");
		symlinkSync("/etc/passwd", join(dir, "link"));
		assert.equal(readTrustedAllowlist(join(dir, "link")), "");
		assert.equal(readTrustedAllowlist(join(dir, "missing")), "");
	} finally { rmSync(dir, { recursive: true, force: true }); }
});

test("leitura confiável aceita arquivo regular protegido com dono root", () => {
	assert.equal(readTrustedAllowlist("/etc/passwd"), readFileSync("/etc/passwd", "utf8"));
});

const pattern = "/usr/bin/keepassxc-cli show -q -t <db> <entrada>";

test("seam 2: permite apenas o formato show -q -t, nunca show -s ou export", () => {
	assert.equal(classifySecretRequest(["/usr/bin/keepassxc-cli", "show", "-q", "-t", "db.kdbx", "npm"], pattern), "allowed");
	assert.equal(classifySecretRequest(["/usr/bin/keepassxc-cli", "show", "-s", "db.kdbx", "npm"], pattern), "unverified");
	assert.equal(classifySecretRequest(["/usr/bin/keepassxc-cli", "export", "db.kdbx"], pattern), "unverified");
});

test("seam 2: comentários, vazio e marcadores preservam os limites do argv", () => {
	const argv = ["/usr/bin/keepassxc-cli", "show", "-q", "-t", "meu cofre.kdbx", "npm"];
	assert.equal(classifySecretRequest(argv, ""), "unverified");
	assert.equal(classifySecretRequest(argv, ` # ${pattern}\n\n`), "unverified");
	assert.equal(classifySecretRequest(argv, `# exemplo\n\n ${pattern}\n`), "allowed");
	for (const args of [argv.slice(0, -1), [...argv, "extra"], [...argv.slice(0, -1), ""], [...argv.slice(0, -1), "-s"]]) {
		assert.equal(classifySecretRequest(args, pattern), "unverified");
	}
	assert.equal(classifySecretRequest(argv, pattern.replace("<entrada>", "*")), "unverified");
	assert.equal(classifySecretRequest(argv, pattern.replace("/usr/bin/", "")), "unverified");
});
