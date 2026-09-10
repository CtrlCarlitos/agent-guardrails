// The thin opencode plugin that delegates all policy logic to the guardrail
// binary. See ../../DESIGN.md "Planes & adapters" and docs/adr/0007.
// This file is embedded in the guardrail binary (opencode_embed.go) and
// written out by `guardrail gen-config opencode --merge` — it is not meant
// to be hand-edited in place; edit this source and rebuild instead.
import { spawnSync } from "node:child_process";

// Absolute path baked in by `guardrail gen-config opencode` at deploy time.
// Deliberately NOT read from the environment: an agent that can set
// GUARDRAIL_BIN could otherwise point the enforcer at /bin/true.
const GUARDRAIL_BIN = "__GUARDRAIL_BIN__";

// Adapter contract mirrored by maxOpencodeHookEnvelopeBytes in internal/adapter/opencode.go.
const MAX_OPENCODE_HOOK_ENVELOPE_BYTES = 8 * 1024 * 1024;

function callGuardrail(envelope) {
	const serializedEnvelope = JSON.stringify(envelope);
	if (Buffer.byteLength(serializedEnvelope, "utf8") > MAX_OPENCODE_HOOK_ENVELOPE_BYTES) {
		throw new Error("guardrail: OpenCode hook envelope exceeds 8 MiB; failing closed");
	}
	const res = spawnSync(GUARDRAIL_BIN, ["hook", "opencode"], {
		input: serializedEnvelope,
		encoding: "utf8",
		timeout: 15000,
	});
	if (res.error) {
		throw new Error(`guardrail: could not run (${res.error.message}); failing closed`);
	}
	if (res.signal) {
		throw new Error(`guardrail: killed by signal ${res.signal}; failing closed`);
	}
	let decision;
	try {
		decision = JSON.parse(res.stdout || "{}");
	} catch {
		throw new Error(`guardrail: unparseable response; failing closed. stderr: ${res.stderr}`);
	}
	if (res.stderr) {
		process.stderr.write(res.stderr);
	}
	if (decision.decision !== "allow") {
		const reason = decision.reason || "no decision returned";
		if (decision.decision === "ask") {
			throw new Error(`guardrail needs confirmation \u2014 ${reason}. Ask the user; if they approve, re-run this exact tool call.`);
		}
		throw new Error(`guardrail: ${reason}`);
	}
	if (res.status !== 0) {
		throw new Error(`guardrail: exited ${res.status}; failing closed`);
	}
	return decision;
}

export const GuardrailPlugin = async ({ directory, client }) => {
	return {
		"tool.execute.before": async (input, output) => {
			const tool = input.tool;
			const args = output.args ?? {};
			const envelope = {
				session_id: input.sessionID ?? input.session_id,
				event: "pre",
				tool,
				cwd: directory,
				arguments: args,
			};
			if (tool === "bash") {
				envelope.command = args.command;
			} else {
				const p = args.filePath ?? args.path ?? args.dirPath ?? args.directory;
				if (p) envelope.paths = [p];
			}
			const decision = callGuardrail(envelope);
			if (decision.reason?.startsWith("NIGHT MODE until ")) {
				const message = decision.reason.split(";", 1)[0];
				if (client?.tui?.showToast) {
					try {
						await client.tui.showToast({
							body: { title: "Guardrail Night Mode", message, variant: "warning", duration: 7000 },
						});
					} catch {
						process.stderr.write(`${message}\n`);
					}
				} else {
					process.stderr.write(`${message}\n`);
				}
			}
		},
	};
};

export default GuardrailPlugin;
