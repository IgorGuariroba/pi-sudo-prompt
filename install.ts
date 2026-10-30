import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { shellQuote } from "./protocol.ts";

export function installationHint(installer: string): string {
	return `/sudo-prompt install-broker (no TUI), ou manualmente: sudo sh ${shellQuote(installer)}`;
}

/** User command only: never register this operation as a model-callable tool. */
export function registerInstallCommand(
	pi: Pick<ExtensionAPI, "registerCommand">,
	options: { installer: string; run: (command: string, cwd: string) => Promise<{ exitCode: number | null }> },
): void {
	pi.registerCommand("sudo-prompt", {
		description: "Instalar ou atualizar o broker: /sudo-prompt install-broker",
		async handler(args, ctx) {
			if (ctx.mode !== "tui") {
				ctx.ui.notify("A instalação do broker exige o TUI interativo do pi (modal do sudo).", "error");
				return;
			}
			if (args.trim() !== "install-broker") {
				ctx.ui.notify("Uso: /sudo-prompt install-broker", "info");
				return;
			}
			let installed = false;
			try {
				installed = (await options.run(`sudo sh ${shellQuote(options.installer)}`, ctx.cwd)).exitCode === 0;
			} catch {
				// Process errors/output are not forwarded to the agent or persisted in the session.
			}
			ctx.ui.notify(
				installed ? "Broker instalado/atualizado." : "Falha ou cancelamento ao instalar o broker; verifique o instalador manual.",
				installed ? "info" : "error",
			);
		},
	});
}
