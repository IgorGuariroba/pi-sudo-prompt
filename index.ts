/**
 * pi-sudo-prompt — secure sudo password prompt for pi.
 *
 * When a command run by the agent (bash tool) or by the user (`!`/`!!`) calls sudo,
 * sudo runs the askpass helper (SUDO_ASKPASS). The helper asks this extension over a
 * private Unix socket; the extension shows a masked modal; the password goes back
 * UI → socket → helper → sudo's stdin pipe. It never enters tool output or the session.
 *
 * See docs/adr/0001-askpass-socket.md for why askpass + socket instead of PTY scraping.
 *
 * Secret requests for consumers other than sudo (`pi-secret-run`, ADR 0002) use the same
 * socket: the root broker asks, the extension checks it is the genuine broker and shows the
 * secret request modal, the broker hands the secret to the consumer's stdin.
 */

import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { Server, Socket } from "node:net";
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
import { SecretRequestModal, SudoPromptModal } from "./modal.ts";
import {
	ENV_SECRET,
	ENV_SOCKET,
	launcherScript,
	MAX_SKEW_MS,
	procInfo,
	readCmdline,
	SUDO_FUNCTION,
	shellQuote,
	validateRequester,
} from "./protocol.ts";
import { classifySecretRequest, readTrustedAllowlist } from "./allowlist.ts";
import { PROTOCOL_VERSION, type SecretRequest, secretRunScript, validateSecretRequest } from "./secret.ts";
import { createRequestServer, ModalQueue, type Reply, type RequestHandler } from "./socket.ts";

const PROMPT_TIMEOUT_MS = 120_000;
const MAX_ATTEMPTS = 3; // sudoers passwd_tries default

const extensionDir = dirname(fileURLToPath(import.meta.url));
const helperScript = join(extensionDir, "askpass.mjs");
const INSTALL_HINT = `sudo sh ${shellQuote(join(extensionDir, "broker", "install.sh"))}`;

interface Bridge {
	dir: string;
	socketPath: string;
	askpassPath: string;
	secret: string;
	server: Server;
	attempts: Map<number, number>;
	/** Broker tickets already honored: a secret request is never answered twice. */
	tickets: Set<string>;
	openModals: Set<{ cancel(): void }>;
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
	/** Holds `pi-secret-run`, on the PATH in every mode so that it can refuse with a reason. */
	let binDir: string | undefined;
	let uiContext: ExtensionContext | undefined;
	const modals = new ModalQueue();

	function withSecretRun(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
		if (!binDir) return env;
		const path = env.PATH ?? process.env.PATH ?? "";
		return { ...env, PATH: [binDir, path].filter(Boolean).join(delimiter) };
	}

	function injectAskpass(context: BashSpawnContext): BashSpawnContext {
		const env = withSecretRun(context.env);
		if (!bridge) return { ...context, env };
		return {
			command: `${SUDO_FUNCTION}\n${context.command}`,
			cwd: context.cwd,
			env: {
				...env,
				SUDO_ASKPASS: bridge.askpassPath,
				[ENV_SOCKET]: bridge.socketPath,
				[ENV_SECRET]: bridge.secret,
			},
		};
	}

	type ModalArgs = Parameters<Parameters<ExtensionContext["ui"]["custom"]>[0]>;
	type ModalFactory = (
		tui: ModalArgs[0],
		theme: ModalArgs[1],
		keybindings: ModalArgs[2],
		done: (value: string | undefined) => void,
	) => SudoPromptModal | SecretRequestModal;

	/** Shows a masked modal; closes it when the requester goes away. Undefined = cancelled/no UI. */
	async function showModal(socket: Socket, create: ModalFactory): Promise<string | undefined> {
		const ctx = uiContext;
		if (!bridge || !ctx || socket.destroyed) return undefined;
		let modal: SudoPromptModal | SecretRequestModal | undefined;
		const onClose = () => modal?.cancel();
		socket.once("close", onClose);
		try {
			return await ctx.ui.custom<string | undefined>((tui, theme, keybindings, done) => {
				modal = create(tui, theme, keybindings, done);
				bridge?.openModals.add(modal);
				if (socket.destroyed) modal.cancel();
				return modal;
			});
		} finally {
			socket.off("close", onClose);
			if (modal) bridge?.openModals.delete(modal);
		}
	}

	async function askUser(socket: Socket, reply: Reply, id: string, prompt: string, sudoPid: number, attempt: number) {
		if (!uiContext) return reply({ type: "password_denied", id, reason: "no UI" });
		const request = { prompt, command: displayCommand(sudoPid), attempt, maxAttempts: MAX_ATTEMPTS, timeoutMs: PROMPT_TIMEOUT_MS };
		const password = await showModal(socket, (tui, theme, keybindings, done) => new SudoPromptModal(tui, theme, keybindings, request, done));
		if (password === undefined) reply({ type: "password_denied", id, reason: "authentication cancelled" });
		else reply({ type: "password_response", id, password });
	}

	/** pi-secret-run, via the root broker (ADR 0002). No cache: every request opens the modal. */
	const handleSecretRequest: RequestHandler = (message, reply, socket) => {
		if (!bridge) return void socket.destroy();
		const { id } = message;
		const deny = (reason: string) => reply({ type: "secret_denied", id, reason });
		const invalid = validateSecretRequest(message, {
			expectedVersion: PROTOCOL_VERSION,
			usedTickets: bridge.tickets,
			reinstallHint: INSTALL_HINT,
		});
		if (invalid) return deny(invalid);
		const { argv, label } = message as SecretRequest;
		modals
			.run(async () => {
				if (!uiContext) return deny("no interactive pi TUI to show the secret prompt");
				const classification = classifySecretRequest(argv, readTrustedAllowlist());
				const secret = await showModal(
					socket,
					(tui, theme, keybindings, done) =>
						new SecretRequestModal(tui, theme, keybindings, { argv, label, classification, timeoutMs: PROMPT_TIMEOUT_MS }, done),
				);
				if (secret === undefined) deny("secret request cancelled or timed out");
				else reply({ type: "secret_response", id, secret });
			})
			.catch(() => deny("prompt failed"));
	};

	/** sudo, via the askpass helper (ADR 0001). */
	const handlePasswordRequest: RequestHandler = (message, reply, socket) => {
		if (!bridge) return void socket.destroy();
		const { id } = message;
		const deny = (reason: string) => reply({ type: "password_denied", id, reason });

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
		modals.run(() => askUser(socket, reply, id, prompt, sudoPid, attempt)).catch(() => deny("prompt failed"));
	};

	function startBridge(): void {
		if (bridge) return;
		const dir = mkdtempSync(join(process.env.XDG_RUNTIME_DIR || tmpdir(), "pi-sudo-prompt-")); // 0700
		const socketPath = join(dir, "askpass.sock");
		const askpassPath = join(dir, "pi-askpass");
		const secret = randomBytes(32).toString("hex");
		writeFileSync(askpassPath, launcherScript({ nodePath: process.execPath, helperScript, socketPath, secret }), {
			mode: 0o700,
		});

		const server = createRequestServer({
			secret: () => bridge?.secret,
			handlers: { password_request: handlePasswordRequest, secret_request: handleSecretRequest },
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
			tickets: new Set(),
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

	function createBinDir(): void {
		if (binDir) return;
		binDir = mkdtempSync(join(process.env.XDG_RUNTIME_DIR || tmpdir(), "pi-secret-run-")); // 0700
		writeFileSync(join(binDir, "pi-secret-run"), secretRunScript({ installHint: INSTALL_HINT }), { mode: 0o700 });
	}

	pi.on("session_start", (_event, ctx) => {
		createBinDir();
		// Custom terminal components exist only in the interactive TUI (not print/json/RPC).
		if (ctx.mode !== "tui" || process.platform !== "linux") return;
		uiContext = ctx;
		startBridge();
	});

	pi.on("session_shutdown", () => {
		uiContext = undefined;
		stopBridge();
		if (binDir) rmSync(binDir, { recursive: true, force: true });
		binDir = undefined;
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
			'Secrets other than the sudo password (vault master password, API key, login token): run `pi-secret-run --label "<what it is for>" -- <cmd> <args>`. In the interactive TUI it opens a masked secret prompt for the user and a root broker feeds the secret to <cmd> on stdin (e.g. `pi-secret-run --label "KeePassXC master password" -- keepassxc-cli show -q -t db.kdbx npm`). Never ask the user to paste a secret in the chat. If it refuses (no broker, no TUI, cancelled), tell the user why instead of working around it.',
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
		if (!bridge && !binDir) return;
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
