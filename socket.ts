// Private socket server of the extension: one signed JSON request per connection, dispatched
// by its `type` to a handler. Also the queue that serializes modals from every origin.
//
// Must stay a .ts module without pi imports: pi's jiti reloads .ts on `/reload` (ADR 0001),
// and tests load it straight from node.

import { createServer, type Server, type Socket } from "node:net";
import { type Message, sign, verify } from "./protocol.ts";

const MAX_LINE = 64 * 1024;

/** Sends one signed message and closes the connection. Later calls are ignored. */
export type Reply = (message: Record<string, unknown>) => void;

/** Handles a request whose signature was already verified. */
export type RequestHandler = (message: Message & { id: string }, reply: Reply, socket: Socket) => void;

export function createRequestServer(options: {
	/** Current session secret; undefined when the bridge is gone (connection is dropped). */
	secret: () => string | undefined;
	handlers: Record<string, RequestHandler>;
}): Server {
	const { secret, handlers } = options;

	function handle(socket: Socket, line: string): void {
		const key = secret();
		if (!key) return void socket.destroy();
		let message: any;
		try {
			message = JSON.parse(line);
		} catch {
			return void socket.destroy();
		}
		const id = typeof message?.id === "string" ? message.id : "";
		const reply: Reply = (answer) => {
			if (secret() !== key || socket.destroyed || socket.writableEnded) return;
			socket.end(`${JSON.stringify(sign(key, answer))}\n`);
		};

		// The sudo helper only understands password_* answers; keep that reply for forgeries.
		if (!verify(key, message)) return reply({ type: "password_denied", id, reason: "bad signature" });
		const handler = Object.hasOwn(handlers, message.type) ? handlers[message.type] : undefined;
		if (!handler) return reply({ type: "request_denied", id, reason: "unknown request type" });
		handler({ ...message, id }, reply, socket);
	}

	return createServer((socket) => {
		socket.setEncoding("utf8");
		let buffer = "";
		let handled = false;
		socket.on("data", (chunk: string) => {
			if (handled) return;
			buffer += chunk;
			const newline = buffer.indexOf("\n");
			if (newline === -1) {
				if (buffer.length > MAX_LINE) socket.destroy();
				return;
			}
			const line = buffer.slice(0, newline);
			buffer = "";
			handled = true;
			handle(socket, line);
		});
		socket.on("error", () => {});
	});
}

/** Runs modal tasks one at a time, in arrival order, whatever request type they come from. */
export class ModalQueue {
	private tail: Promise<unknown> = Promise.resolve();

	run<T>(task: () => Promise<T>): Promise<T> {
		const result = this.tail.then(task);
		this.tail = result.catch(() => {});
		return result;
	}
}
