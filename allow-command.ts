import type { ExtensionCommandContext } from "@earendil-works/pi-coding-agent";
import { ALLOWLIST_PATH, classifySecretRequest, type SecretClassification } from "./allowlist.ts";
import { shellQuote } from "./protocol.ts";

/** Runs as root via the existing sudo bridge; never uses a user-writable temporary file. */
const APPEND_PATTERN = `import os, stat, sys, fcntl
path, pattern = sys.argv[1:]
if os.geteuid() != 0:
    raise SystemExit("root required")
for parent in ("/", "/etc", "/etc/pi-sudo-prompt"):
    info = os.lstat(parent)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise SystemExit("unsafe allowlist directory")
fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, "r+", encoding="utf-8") as target:
    fcntl.flock(target, fcntl.LOCK_EX)
    info = os.fstat(target.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise SystemExit("unsafe allowlist file")
    text = target.read()
    if pattern not in text.splitlines():
        target.write(("\\n" if text and not text.endswith("\\n") else "") + pattern + "\\n")
        target.flush()
        os.fsync(target.fileno())
`;

export function allowWriteCommand(pattern: string): string {
	return `sudo /usr/bin/python3 -I -c ${shellQuote(APPEND_PATTERN)} ${shellQuote(ALLOWLIST_PATH)} ${shellQuote(pattern)}`;
}

/** Conservative suggestion: only the familiar OTP format is generalized automatically. */
function propose(argv: readonly string[]): string {
	if (argv[0].endsWith("/keepassxc-cli") && argv.length === 6 && argv.slice(1, 4).join(" ") === "show -q -t") {
		return `${argv[0]} show -q -t <db> <entrada>`;
	}
	return argv.join(" ");
}

/** Session-local argv only, never the secret or the agent's label. */
export function createAllowCommand(options: {
	run: (command: string, cwd: string) => Promise<{ exitCode: number | null }>;
}) {
	let last: string[] | undefined;
	let generation = 0;
	return {
		observe(argv: readonly string[], classification: SecretClassification) {
			if (classification === "unverified") last = [...argv];
		},
		reset() { last = undefined; generation++; },
		async handler(ctx: ExtensionCommandContext): Promise<void> {
			if (ctx.mode !== "tui") {
				ctx.ui.notify("Liberar um formato exige o TUI interativo do pi.", "error");
				return;
			}
			const session = generation;
			const argv = last;
			if (!argv) {
				ctx.ui.notify("Nenhum pedido de segredo não verificado foi mostrado nesta sessão.", "error");
				return;
			}
			const edited = await ctx.ui.editor("Liberar formato: <nome> corresponde a um argumento sem prefixo -", propose(argv));
			if (edited === undefined || session !== generation) return;
			const pattern = edited.trim().replace(/[ \t]+/g, " ");
			if (/[\r\n\x00-\x1f\x7f]/.test(edited) || !pattern || classifySecretRequest(argv, pattern) !== "allowed") {
				ctx.ui.notify("Formato inválido: use uma única linha, caminho absoluto e um padrão que corresponda ao pedido anterior.", "error");
				return;
			}
			if (!(await ctx.ui.confirm("Gravar formato na allowlist?", `${pattern}\n\nPedidos correspondentes deixarão de mostrar o aviso vermelho. Só confirme se o consumidor não revelar o segredo. A gravação usa sudo (pode haver credenciais em cache).`))) return;
			if (session !== generation) return;
			let saved = false;
			try { saved = (await options.run(allowWriteCommand(pattern), ctx.cwd)).exitCode === 0; } catch { /* No process output in session. */ }
			ctx.ui.notify(saved ? "Formato gravado na allowlist." : "Falha ou cancelamento ao gravar; instale o broker e confira dono root e permissões da allowlist.", saved ? "info" : "error");
		},
	};
}
