import type { KeybindingsManager, Theme } from "@earendil-works/pi-coding-agent";
import {
	type Component,
	CURSOR_MARKER,
	decodeKittyPrintable,
	type Focusable,
	renderFakeCursor,
	type TUI,
	truncateToWidth,
	visibleWidth,
} from "@earendil-works/pi-tui";
import { SUDO_MODAL_TITLE } from "./protocol.ts";
import { secretModalContent } from "./secret.ts";

export interface SudoPromptRequest {
	/** Prompt text sudo passed to the askpass helper, e.g. "[sudo] senha para movida: ". */
	prompt: string;
	/** Command line of the sudo process asking for the password. */
	command: string;
	/** 1-based attempt number for this sudo process. */
	attempt: number;
	maxAttempts: number;
	timeoutMs: number;
}

const PASTE_START = "\x1b[200~";
const PASTE_END = "\x1b[201~";

/**
 * Masked input modal. Resolves `done(password)` on Enter, `done(undefined)` on Escape or
 * timeout. The password lives only in this component's memory and is never rendered.
 * Subclasses only provide the body text.
 */
abstract class MaskedPromptModal implements Component, Focusable {
	focused = false;
	private password = "";
	private inPaste = false;
	private pasteBuffer = "";
	private finished = false;
	private readonly deadline: number;
	private readonly timer: NodeJS.Timeout;

	constructor(
		private readonly tui: TUI,
		protected readonly theme: Theme,
		private readonly keybindings: KeybindingsManager,
		timeoutMs: number,
		private readonly done: (password: string | undefined) => void,
	) {
		this.deadline = Date.now() + timeoutMs;
		this.timer = setInterval(() => {
			if (Date.now() >= this.deadline) this.finish(undefined);
			else this.tui.requestRender();
		}, 1000);
	}

	/** Close from outside (sudo exited, tool aborted, session shutdown). */
	cancel(): void {
		this.finish(undefined);
	}

	private finish(result: string | undefined): void {
		if (this.finished) return;
		this.finished = true;
		clearInterval(this.timer);
		this.password = "";
		this.done(result);
	}

	dispose(): void {
		clearInterval(this.timer);
		this.password = "";
	}

	invalidate(): void {}

	handleInput(data: string): void {
		if (this.finished) return;

		if (data.includes(PASTE_START)) {
			this.inPaste = true;
			this.pasteBuffer = "";
			data = data.replace(PASTE_START, "");
		}
		if (this.inPaste) {
			this.pasteBuffer += data;
			const end = this.pasteBuffer.indexOf(PASTE_END);
			if (end === -1) return;
			this.password += this.pasteBuffer.slice(0, end).replace(/[\r\n]/g, "");
			const rest = this.pasteBuffer.slice(end + PASTE_END.length);
			this.inPaste = false;
			this.pasteBuffer = "";
			this.tui.requestRender();
			if (rest) this.handleInput(rest);
			return;
		}

		const kb = this.keybindings;
		if (kb.matches(data, "tui.select.cancel")) return this.finish(undefined);
		if (kb.matches(data, "tui.input.submit") || data === "\n" || data === "\r") return this.finish(this.password);
		if (kb.matches(data, "tui.editor.deleteCharBackward")) {
			this.password = Array.from(this.password).slice(0, -1).join("");
		} else if (
			kb.matches(data, "tui.editor.deleteToLineStart") ||
			kb.matches(data, "tui.editor.deleteWordBackward")
		) {
			this.password = "";
		} else {
			const printable = decodeKittyPrintable(data) ?? (isPrintable(data) ? data : undefined);
			if (!printable) return;
			this.password += printable;
		}
		this.tui.requestRender();
	}

	/** Lines above and below the password field; `clock` is the time left before auto-cancel. */
	protected abstract body(clock: string): { before: string[]; after: string[] };

	render(width: number): string[] {
		const t = this.theme;
		const border = (s: string) => t.fg("warning", s);
		const inner = Math.max(10, width - 4); // "│ " + content + " │"

		const remaining = Math.max(0, Math.ceil((this.deadline - Date.now()) / 1000));
		const clock = `${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, "0")}`;

		const passwordLine = (() => {
			const label = t.fg("success", "Password: ");
			const cursor = this.focused ? `${CURSOR_MARKER}${renderFakeCursor(" ")}` : "";
			if (!this.password) return `${label}${t.fg("dim", "Enter password...")}${cursor}`;
			return `${label}${t.fg("text", "•".repeat(Array.from(this.password).length))}${cursor}`;
		})();

		const { before, after } = this.body(clock);
		const body = [...before, passwordLine, ...after];

		const lines = [border(`╭${"─".repeat(inner + 2)}╮`)];
		for (const line of body) {
			const fitted = truncateToWidth(line, inner);
			const pad = " ".repeat(Math.max(0, inner - visibleWidth(fitted)));
			lines.push(`${border("│")} ${fitted}${pad} ${border("│")}`);
		}
		lines.push(border(`╰${"─".repeat(inner + 2)}╯`));
		return lines;
	}
}

/** Masked password modal shaped like Cursor's "Sudo Authentication Required". */
export class SudoPromptModal extends MaskedPromptModal {
	constructor(
		tui: TUI,
		theme: Theme,
		keybindings: KeybindingsManager,
		private readonly request: SudoPromptRequest,
		done: (password: string | undefined) => void,
	) {
		super(tui, theme, keybindings, request.timeoutMs, done);
	}

	protected body(clock: string) {
		const t = this.theme;
		const before: string[] = [
			"",
			`🔐 ${t.bold(SUDO_MODAL_TITLE)}`,
			"",
			`${t.fg("dim", "Command:")} ${t.fg("text", this.request.command)}`,
			"",
			t.fg("text", this.request.prompt.trimEnd()),
			"",
		];
		if (this.request.attempt > 1) {
			before.push(
				t.fg("error", `Incorrect password, try again (${this.request.attempt}/${this.request.maxAttempts})`),
				"",
			);
		}
		const after = [
			"",
			t.fg("dim", `Press Enter to submit, Escape to cancel · auto-cancel in ${clock}`),
			"",
			t.italic(t.fg("dim", "Your password is secure and will not be visible to the AI model.")),
			"",
		];
		return { before, after };
	}
}

export interface SecretRequestView {
	/** Real argv of the consumer, read by the root broker. */
	argv: string[];
	/** Description written by the agent (not verified). */
	label: string;
	timeoutMs: number;
}

/** Secret request modal (pi-secret-run, ADR 0002). Its title is never the sudo one. */
export class SecretRequestModal extends MaskedPromptModal {
	constructor(
		tui: TUI,
		theme: Theme,
		keybindings: KeybindingsManager,
		private readonly request: SecretRequestView,
		done: (secret: string | undefined) => void,
	) {
		super(tui, theme, keybindings, request.timeoutMs, done);
	}

	protected body(clock: string) {
		const t = this.theme;
		const { title, lines } = secretModalContent(this.request);
		const styled = lines.map(({ text, style }) => {
			if (style === "error") return t.bold(t.fg("error", text));
			if (style === "label") return t.italic(t.fg("text", text));
			return t.fg(style, text);
		});
		const before = ["", `🔑 ${t.bold(title)}`, "", ...styled, ""];
		const after = [
			"",
			t.fg("dim", `Enter envia, Escape cancela · cancela sozinho em ${clock}`),
			"",
			t.italic(t.fg("dim", "O segredo vai direto para o comando; o modelo não o vê.")),
			"",
		];
		return { before, after };
	}
}

function isPrintable(data: string): boolean {
	if (!data || data.startsWith("\x1b")) return false;
	for (const ch of data) {
		const code = ch.codePointAt(0) ?? 0;
		if (code < 0x20 || code === 0x7f) return false;
	}
	return true;
}
