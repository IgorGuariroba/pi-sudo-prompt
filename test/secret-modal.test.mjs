// Seam: what the secret request modal says (the component in modal.ts only draws these lines).
import assert from "node:assert/strict";
import { test } from "node:test";
import { SUDO_MODAL_TITLE } from "../protocol.ts";
import { secretModalContent } from "../secret.ts";

const content = secretModalContent({
	argv: ["/usr/bin/keepassxc-cli", "show", "-q", "-t", "meu cofre.kdbx", "npm"],
	label: "senha mestra do KeePassXC",
});
const text = (lines) => lines.map((line) => line.text).join("\n");

test("has its own title, never the sudo one", () => {
	assert.ok(content.title);
	assert.notEqual(content.title, SUDO_MODAL_TITLE);
	assert.ok(!content.title.toLowerCase().includes("sudo"));
});

test("shows the real argv read by the broker, quoted like a shell command", () => {
	assert.match(text(content.lines), /\/usr\/bin\/keepassxc-cli show -q -t 'meu cofre\.kdbx' npm/);
});

test("shows the agent's description marked as not verified", () => {
	const line = content.lines.find((l) => l.text.includes("senha mestra do KeePassXC"));
	assert.ok(line, "description missing");
	assert.match(text(content.lines), /não verificada/);
});

test("always carries the red warning in this phase", () => {
	const warning = content.lines.find((l) => l.style === "error");
	assert.ok(warning);
	assert.match(warning.text, /este comando pode mostrar ao agente o que você digitar/);
});

test("terminal control characters from the agent are shown escaped, never interpreted", () => {
	const hostile = secretModalContent({ argv: ["/bin/cat", "\x1b[2J\x1b[Hfake"], label: "a\x1b]0;x\x07b\nc" });
	const all = text(hostile.lines);
	assert.ok(!/[\x00-\x08\x0b-\x1f\x7f]/.test(all), "raw control character reached the modal");
	assert.match(all, /\\x1b\[2J/);
});
