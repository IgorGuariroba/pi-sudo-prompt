/**
 * pi-sudo-prompt — secure sudo password prompt for pi.
 *
 * When a command run by the agent (bash tool) or by the user (`!`/`!!`) calls sudo,
 * sudo runs the askpass helper (SUDO_ASKPASS). The helper asks this extension over a
 * private Unix socket; the extension shows a masked modal; the password goes back
 * UI → socket → helper → sudo's stdin pipe. It never enters tool output or the session.
 *
 * See docs/adr/0001-askpass-socket.md for why askpass + socket instead of PTY scraping.
 */

import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
	type BashOperations,
	type BashSpawnContext,
	createBashToolDefinition,
	createLocalBashOperations,
	type ExtensionAPI,
	type ExtensionContext,
	getAgentDir,
	SettingsManager,
} from "@earendil-works/pi-coding-agent";
import { SudoPromptModal } from "./modal.ts";
import {
	ENV_SECRET,
	ENV_SOCKET,
	launcherScript,
	MAX_SKEW_MS,
	procInfo,
	readCmdline,
	SUDO_FUNCTION,
	shellQuote,
	sign,
	validateRequester,
	verify,
} from "./protocol.ts";

const PROMPT_TIMEOUT_MS = 120_000;
const MAX_ATTEMPTS = 3; // sudoers passwd_tries default

const extensionDir = dirname(fileURLToPath(import.meta.url));
const helperScript = join(extensionDir, "askpass.mjs");

interface Bridge {
	dir: string;
	socketPath: string;
	askpassPath: string;
	secret: string;
	server: Server;
	attempts: Map<number, number>;
	openModals: Set<SudoPromptModal>;
}

function displayCommand(sudoPid: number): string {
	const argv = readCmdline(sudoPid);
	if (argv.length === 0) return "sudo";
	argv[0] = basename(argv[0]);
	const injected = argv.indexOf("-A");
	if (injected === 1) argv.splice(1, 1);
	return argv.map((arg) => (/^[\w@%+=:,./-]+$/.test(arg) ? arg : shellQuote(arg))).join(" ");
}

export default function sudoPrompt(pi: ExtensionAPI) {
	let bridge: Bridge | undefined;
	let uiContext: ExtensionContext | undefined;
	let queue: Promise<void> = Promise.resolve();

	function injectAskpass(context: BashSpawnContext): BashSpawnContext {
		if (!bridge) return context;
		return {
			command: `${SUDO_FUNCTION}\n${context.command}`,
			cwd: context.cwd,
			env: {
				...context.env,
				SUDO_ASKPASS: bridge.askpassPath,
				[ENV_SOCKET]: bridge.socketPath,
				[ENV_SECRET]: bridge.secret,
			},
		};
	}

	function reply(socket: Socket, message: Record<string, unknown>): void {
		if (!bridge || socket.destroyed) return;
		socket.end(`${JSON.stringify(sign(bridge.secret, message))}\n`);
	}

	async function askUser(socket: Socket, id: string, prompt: string, sudoPid: number, attempt: number) {
		const ctx = uiContext;
		if (!bridge || !ctx || socket.destroyed) return reply(socket, { type: "password_denied", id, reason: "no UI" });

		let modal: SudoPromptModal | undefined;
		const onClose = () => modal?.cancel();
		socket.once("close", onClose);
		try {
			const password = await ctx.ui.custom<string | undefined>((tui, theme, keybindings, done) => {
				modal = new SudoPromptModal(
					tui,
					theme,
					keybindings,
					{ prompt, command: displayCommand(sudoPid), attempt, maxAttempts: MAX_ATTEMPTS, timeoutMs: PROMPT_TIMEOUT_MS },
					done,
				);
				bridge?.openModals.add(modal);
				if (socket.destroyed) modal.cancel();
				return modal;
			});
			if (password === undefined) reply(socket, { type: "password_denied", id, reason: "authentication cancelled" });
			else reply(socket, { type: "password_response", id, password });
		} finally {
			socket.off("close", onClose);
			if (modal) bridge?.openModals.delete(modal);
		}
	}

	function handleRequest(socket: Socket, line: string): void {
		if (!bridge) return void socket.destroy();
		let message: any;
		try {
			message = JSON.parse(line);
		} catch {
			return void socket.destroy();
		}
		const id = typeof message?.id === "string" ? message.id : "";
		const deny = (reason: string) => reply(socket, { type: "password_denied", id, reason });

		if (!verify(bridge.secret, message) || message.type !== "password_request") return deny("bad signature");
		if (Math.abs(Date.now() - Number(message.ts)) > MAX_SKEW_MS) return deny("stale request");

		// Server-side re-check: the requester must be the genuine askpass helper, child of a root sudo.
		const helperPid = Number(message.pid);
		const sudoPid = Number(message.ppid);
		const invalid = validateRequester({
			helperPid,
			sudoPid,
			helperScript,
			nodePath: process.execPath,
			socketPath: bridge.socketPath,
			secret: bridge.secret,
			uid: process.getuid?.() ?? -1,
		});
		if (invalid) return deny(invalid);

		for (const pid of bridge.attempts.keys()) if (!procInfo(pid)) bridge.attempts.delete(pid);
		const attempt = (bridge.attempts.get(sudoPid) ?? 0) + 1;
		bridge.attempts.set(sudoPid, attempt);

		const prompt = typeof message.prompt === "string" ? message.prompt : "Password:";
		queue = queue.then(() => askUser(socket, id, prompt, sudoPid, attempt)).catch(() => deny("prompt failed"));
	}

	function startBridge(): void {
		if (bridge) return;
		const dir = mkdtempSync(join(process.env.XDG_RUNTIME_DIR || tmpdir(), "pi-sudo-prompt-")); // 0700
		const socketPath = join(dir, "askpass.sock");
		const askpassPath = join(dir, "pi-askpass");
		const secret = randomBytes(32).toString("hex");
		writeFileSync(askpassPath, launcherScript({ nodePath: process.execPath, helperScript, socketPath, secret }), {
			mode: 0o700,
		});

		const server = createServer((socket) => {
			socket.setEncoding("utf8");
			let buffer = "";
			let handled = false;
			socket.on("data", (chunk: string) => {
				if (handled) return;
				buffer += chunk;
				const newline = buffer.indexOf("\n");
				if (newline === -1) {
					if (buffer.length > 64 * 1024) socket.destroy();
					return;
				}
				const line = buffer.slice(0, newline);
				buffer = "";
				handled = true;
				handleRequest(socket, line);
			});
			socket.on("error", () => {});
		});
		server.listen(socketPath);
		server.unref();

		bridge = {
			dir,
			socketPath,
			askpassPath,
			secret,
			server,
			attempts: new Map(),
			openModals: new Set(),
		};
	}

	function stopBridge(): void {
		if (!bridge) return;
		const current = bridge;
		bridge = undefined;
		for (const modal of current.openModals) modal.cancel();
		current.server.close();
		rmSync(current.dir, { recursive: true, force: true });
	}

	pi.on("session_start", (_event, ctx) => {
		// Custom terminal components exist only in the interactive TUI (not print/json/RPC).
		if (ctx.mode !== "tui" || process.platform !== "linux") return;
		uiContext = ctx;
		startBridge();
	});

	pi.on("session_shutdown", () => {
		uiContext = undefined;
		stopBridge();
	});

	// Agent bash tool: same as the built-in, plus the askpass environment.
	const template = createBashToolDefinition(process.cwd(), { spawnHook: injectAskpass });
	pi.registerTool({
		...template,
		// Tell the agent the bridge exists; otherwise it assumes sudo can't prompt and gives up.
		promptGuidelines: [
			...(template.promptGuidelines ?? []),
			"sudo works in bash: in the interactive TUI, a plain `sudo <cmd>` opens a masked password modal for the user (pi-sudo-prompt, via SUDO_ASKPASS). Just run the command; never ask the user for the password and never pipe it.",
			"Do not probe sudo with `sudo -n` (non-interactive): it fails without cached credentials even though a normal `sudo` would prompt. Use a timeout long enough for the user to type (e.g. 120s).",
		],
		async execute(toolCallId, params, signal, onUpdate, ctx) {
			let commandPrefix: string | undefined;
			let shellPath: string | undefined;
			try {
				const settings = SettingsManager.create(ctx.cwd, getAgentDir(), { projectTrusted: ctx.isProjectTrusted() });
				commandPrefix = settings.getShellCommandPrefix();
				shellPath = settings.getShellPath();
			} catch {
				// fall back to defaults
			}
			const tool = createBashToolDefinition(ctx.cwd, { spawnHook: injectAskpass, commandPrefix, shellPath });
			return tool.execute(toolCallId, params, signal, onUpdate, ctx);
		},
	});

	// User `!` / `!!` commands.
	pi.on("user_bash", (_event, ctx) => {
		if (!bridge) return;
		let shellPath: string | undefined;
		try {
			shellPath = SettingsManager.create(ctx.cwd, getAgentDir(), { projectTrusted: ctx.isProjectTrusted() }).getShellPath();
		} catch {
			// default shell
		}
		const local = createLocalBashOperations({ shellPath });
		const operations: BashOperations = {
			exec(command, cwd, options) {
				const binDir = join(getAgentDir(), "bin");
				const path = process.env.PATH ?? "";
				const baseEnv = options.env ?? {
					...process.env,
					PATH: path.split(delimiter).includes(binDir) ? path : [binDir, path].filter(Boolean).join(delimiter),
				};
				const injected = injectAskpass({ command, cwd, env: baseEnv });
				return local.exec(injected.command, injected.cwd, { ...options, env: injected.env });
			},
		};
		return { operations };
	});
}
