import assert from "node:assert/strict";
import { test } from "node:test";
import { spawnSync } from "node:child_process";
import { allowWriteCommand, createAllowCommand } from "../allow-command.ts";
import { registerInstallCommand } from "../install.ts";
import { classifySecretRequest } from "../allowlist.ts";
import { shellQuote } from "../protocol.ts";

const argv = ["/usr/bin/keepassxc-cli", "show", "-q", "-t", "/vault.kdbx", "npm"];
function harness({ edit, confirm = true, run = async () => ({ exitCode: 0 }) } = {}) {
 const notices = [], proposals = [], confirmations = [], commands = [];
 const allow = createAllowCommand({ run: async (...args) => { commands.push(args); return run(...args); } });
 const ctx = { mode: "tui", cwd: "/work", ui: {
  notify: (...args) => notices.push(args),
  editor: async (title, prefill) => { proposals.push(prefill); return edit === null ? undefined : edit === undefined ? prefill : edit; },
  confirm: async (...args) => { confirmations.push(args); return confirm; },
 } };
 return { allow, ctx, notices, proposals, confirmations, commands };
}

test("registered /sudo-prompt allow dispatches without becoming a model-callable tool", async () => {
 const h = harness();
 h.allow.observe(argv, "unverified");
 let command;
 registerInstallCommand({ registerCommand(name, options) {
  assert.equal(name, "sudo-prompt"); command = options;
 } }, { installer: "/installer", run: async () => assert.fail("not the installer"), allow: h.allow.handler });
 await command.handler("allow extra", h.ctx);
 assert.equal(h.commands.length, 0);
 await command.handler("allow", h.ctx);
 assert.equal(h.commands.length, 1);
});

test("allow proposes the last unverified format, lets the user edit and confirms before sudo", async () => {
 const h = harness({ edit: "/usr/bin/keepassxc-cli show -q -t <cofre> npm" });
 h.allow.observe(argv, "unverified");
 h.allow.observe(["/usr/bin/true"], "allowed");
 await h.allow.handler(h.ctx);
 assert.deepEqual(h.proposals, ["/usr/bin/keepassxc-cli show -q -t <db> <entrada>"]);
 assert.equal(h.confirmations.length, 1);
 assert.match(h.confirmations[0].join(" "), /<cofre> npm/);
 assert.equal(h.commands.length, 1);
 assert.match(h.commands[0][0], /^sudo \/usr\/bin\/python3 -I -c /);
 assert.match(h.commands[0][0], /<cofre> npm/);
 assert.equal(h.commands[0][1], "/work");
 assert.match(h.notices.at(-1)[0], /gravado/);
 const pattern = "/usr/bin/keepassxc-cli show -q -t <cofre> npm";
 assert.equal(classifySecretRequest(argv, pattern), "allowed");
 assert.equal(classifySecretRequest([argv[0], "show", "-s", "-t", "db", "npm"], pattern), "unverified");
});

test("allow refuses absent history and non-TUI modes, and forgets history on reset", async () => {
 const h = harness();
 await h.allow.handler(h.ctx);
 assert.match(h.notices.at(-1)[0], /Nenhum pedido/);
 h.allow.observe(argv, "unverified");
 for (const mode of ["print", "json", "rpc"]) {
  await h.allow.handler({ ...h.ctx, mode });
  assert.match(h.notices.at(-1)[0], /TUI/);
 }
 h.allow.reset();
 await h.allow.handler(h.ctx);
 assert.match(h.notices.at(-1)[0], /Nenhum pedido/);
 assert.equal(h.proposals.length, 0);
 assert.equal(h.commands.length, 0);
});

test("cancelling either UI dialog never executes sudo, even with cached credentials", async () => {
 for (const options of [{ edit: null }, { confirm: false }]) {
  const h = harness(options);
  h.allow.observe(argv, "unverified");
  await h.allow.handler(h.ctx);
  assert.equal(h.commands.length, 0);
 }
});

test("malformed, multiline and nonmatching patterns cannot be saved", async () => {
 for (const edit of ["", "/usr/bin/cat", "/usr/bin/keepassxc-cli show -s <db> <entrada>", "/usr/bin/keepassxc-cli show -q -t <db> <entrada>\n/usr/bin/cat", "# comment", "keepassxc-cli show -q -t <db> <entrada>"]) {
  const h = harness({ edit });
  h.allow.observe(argv, "unverified");
  await h.allow.handler(h.ctx);
  assert.equal(h.commands.length, 0);
  assert.equal(h.confirmations.length, 0);
  assert.equal(h.notices.at(-1)[1], "error");
 }
});

test("failure, cancellation and process errors do not publish process output", async () => {
 for (const run of [async () => ({ exitCode: 1 }), async () => ({ exitCode: null }), async () => { throw new Error("private-output"); }]) {
  const h = harness({ run });
  h.allow.observe(argv, "unverified");
  await h.allow.handler(h.ctx);
  assert.equal(h.notices.at(-1)[1], "error");
  assert.doesNotMatch(JSON.stringify(h.notices), /private-output/);
 }
});

test("session replacement during approval invalidates the pending operation", async () => {
 const h = harness();
 h.allow.observe(argv, "unverified");
 h.ctx.ui.confirm = async () => { h.allow.reset(); return true; };
 await h.allow.handler(h.ctx);
 assert.equal(h.commands.length, 0);
});

const isolatedRoot = spawnSync("unshare", ["-Ur", "-m", "sh", "-c", "mount -t tmpfs tmpfs /etc"], { encoding: "utf8", timeout: 10000 });
test("root writer preserves content, owner and permissions and rejects unsafe targets", {
 skip: isolatedRoot.status !== 0 ? "isolated root filesystem unavailable (no sudo used)" : false,
}, () => {
 const pattern = "/usr/bin/keepassxc-cli show -q -t <db> <entrada>";
 // Strip only the sudo launcher: the very same writer executes as namespace root.
 const command = allowWriteCommand(pattern).replace(/^sudo /, "");
 const checks = `
  mkdir /etc/pi-sudo-prompt
  printf '# preserved comment' > /etc/pi-sudo-prompt/allowlist
  chmod 0640 /etc/pi-sudo-prompt/allowlist
  ${command}
  ${command}
  test "$(stat -c '%u:%g:%a' /etc/pi-sudo-prompt/allowlist)" = '0:0:640'
  test "$(wc -l < /etc/pi-sudo-prompt/allowlist)" = 2
  grep -qx '# preserved comment' /etc/pi-sudo-prompt/allowlist
  grep -qx '/usr/bin/keepassxc-cli show -q -t <db> <entrada>' /etc/pi-sudo-prompt/allowlist
  cat /etc/pi-sudo-prompt/allowlist
  chmod 0666 /etc/pi-sudo-prompt/allowlist
  if ${command}; then exit 10; fi
  chmod 0640 /etc/pi-sudo-prompt/allowlist
  mv /etc/pi-sudo-prompt/allowlist /etc/original
  ln -s /etc/original /etc/pi-sudo-prompt/allowlist
  if ${command}; then exit 11; fi
  rm /etc/pi-sudo-prompt/allowlist
  if ${command}; then exit 12; fi
  cp /etc/original /etc/pi-sudo-prompt/allowlist
  chmod 0777 /etc/pi-sudo-prompt
  if ${command}; then exit 13; fi
 `;
 // A chroot gives / itself namespace-root ownership too (the host / is unmapped).
 const result = spawnSync("unshare", ["-Ur", "-m", "sh", "-eu", "-c", `
  root=$(mktemp -d)
  trap 'umount -R "$root"; rmdir "$root"' EXIT
  mount -t tmpfs -o mode=0755 tmpfs "$root"
  mkdir "$root/etc" "$root/usr" "$root/bin" "$root/lib" "$root/lib64"
  for dir in /usr /bin /lib /lib64; do mount --bind "$dir" "$root$dir"; done
  chroot "$root" /bin/sh -eu -c ${shellQuote(checks)}
 `], { encoding: "utf8", timeout: 10000 });
 assert.equal(result.status, 0, result.stderr + result.stdout);
 assert.equal(classifySecretRequest([argv[0], "show", "-q", "-t", "other db", "entry"], result.stdout), "allowed");
 assert.equal(classifySecretRequest([argv[0], "show", "-s", "db", "entry"], result.stdout), "unverified");
 assert.equal(classifySecretRequest([argv[0], "export", "db"], result.stdout), "unverified");
});
