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

function isPendingOperatorAction(decision) {
	if (decision?.decision !== "deny" || decision.status !== "pending" || typeof decision.operator_action !== "string" || !decision.operator_action || typeof decision.request_id !== "string" || !decision.request_id || typeof decision.approval_url !== "string") return false;
	try {
		const url = new URL(decision.approval_url);
		return url.protocol === "http:" && url.hostname === "localhost" && /^[1-9][0-9]*$/.test(url.port) && Number(url.port) <= 65535 && !url.username && !url.password && (url.pathname === "" || url.pathname === "/") && !url.search && !url.hash;
	} catch {
		return false;
	}
}

// Spawn latency on Windows (CreateProcess + NTFS + Defender scan) can
// intermittently exceed the timeout even on an idle machine. The engine is
// our own local policy process, not an untrusted call — retry internally
// with backoff before failing closed (#132).
const SPAWN_RETRIES = 2;
const SPAWN_BASE_TIMEOUT_MS = 15000;

// Degraded communication allow (B+): the tool list is baked by gen-config
// from planecontract.DegradedAllow — argument-independent, direct human
// communication only. While the engine is unreachable (transport failure on
// a single short attempt), these calls allow locally, loudly: a stderr
// notice, a reason naming the outage, and a buffered report flushed into
// the next healthy call's envelope so the audit trail keeps the mediation
// evidence. Everything else — including a reachable engine that denies,
// exits non-zero, or returns garbage — still fails closed.
const DEGRADED_ALLOW_TOOLS = new Set("__DEGRADED_ALLOW_TOOLS__");
const DEGRADED_PROBE_TIMEOUT_MS = 5000;
const degradedAllowReports = [];

function callGuardrail(envelope) {
	const serializedEnvelope = JSON.stringify(envelope);
	if (Buffer.byteLength(serializedEnvelope, "utf8") > MAX_OPENCODE_HOOK_ENVELOPE_BYTES) {
		throw new Error("guardrail: OpenCode hook envelope exceeds 8 MiB; failing closed");
	}
	// Piggyback buffered degraded-allow reports on this call; they are only
	// cleared once the engine actually answers.
	const flushReports = degradedAllowReports.length > 0 ? degradedAllowReports.slice(0, 32) : null;
	if (flushReports) envelope.degraded_allows = flushReports;
	let res;
	if (DEGRADED_ALLOW_TOOLS.has(envelope.tool)) {
		// One short attempt: a hung engine must not stall the operator's
		// communication channel behind the retry ladder.
		res = spawnSync(GUARDRAIL_BIN, ["hook", "opencode"], {
			input: serializedEnvelope,
			encoding: "utf8",
			timeout: DEGRADED_PROBE_TIMEOUT_MS,
		});
		if (res.error) {
			degradedAllowReports.push({ tool: envelope.tool, call_id: envelope.call_id || "", ts: new Date().toISOString() });
			process.stderr.write(`[guardrail: engine unreachable; degraded allow for ${envelope.tool} — enforcement is offline for this call]\n`);
			return { decision: "allow", reason: `guardrail: engine unreachable; degraded allow for ${envelope.tool} — enforcement is offline for this call` };
		}
		// The engine answered: fall through to shared handling — a deny or a
		// malformed response must still fail closed, question included.
	} else {
		for (let attempt = 0; attempt <= SPAWN_RETRIES; attempt++) {
			res = spawnSync(GUARDRAIL_BIN, ["hook", "opencode"], {
				input: serializedEnvelope,
				encoding: "utf8",
				timeout: SPAWN_BASE_TIMEOUT_MS + attempt * 10000,
			});
			if (!res.error) break;
			if (attempt < SPAWN_RETRIES) {
				// Brief backoff before retry — Defender scans are transient.
				const waitUntil = Date.now() + 500 * (attempt + 1);
				while (Date.now() < waitUntil) {}
			}
		}
		if (res.error) {
			throw new Error(`guardrail: could not run after ${SPAWN_RETRIES + 1} attempts (${res.error.message}); failing closed`);
		}
	}
	if (flushReports) {
		degradedAllowReports.splice(0, flushReports.length);
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
	const pendingOperatorAction = isPendingOperatorAction(decision);
	if (decision.decision !== "allow" && !pendingOperatorAction) {
		const reason = decision.reason || "no decision returned";
		throw new Error(`guardrail: ${reason}`);
	}
	if (res.status !== 0 && !pendingOperatorAction) {
		throw new Error(`guardrail: exited ${res.status}; failing closed`);
	}
	return decision;
}

// Host-owned approval correlation (ADR-0015): opencode's permission dialog
// is the Approve control; our plugin observes the reply and attributes it to
// the exact call. In-memory only — evidence never crosses processes.
const permissionCallIDs = new Map();
const hostApprovedCallIDs = new Set();
const allowResponses = new Set(["once", "always"]);

async function trackHostApprovals(client) {
	try {
		const stream = await client.event.subscribe();
		for await (const event of stream) {
			const type = event?.type;
			if (type === "permission.updated" && event.properties?.callID && event.properties?.id) {
				permissionCallIDs.set(event.properties.id, event.properties.callID);
			} else if (type === "permission.replied" && event.properties?.permissionID) {
				const callID = permissionCallIDs.get(event.properties.permissionID);
				if (callID && allowResponses.has(String(event.properties.response).toLowerCase())) {
					hostApprovedCallIDs.add(callID);
				}
			}
		}
	} catch {
		// Event stream unavailable: fall back to retry-inference guidance.
	}
}

export const GuardrailPlugin = async ({ directory, client }) => {
	trackHostApprovals(client);
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
			if (input.callID) {
				envelope.call_id = input.callID;
				if (hostApprovedCallIDs.delete(input.callID)) {
					// Consumed exactly once, for this call only.
					envelope.host_approved = true;
				}
			}
			if (tool === "bash") {
				envelope.command = args.command;
			} else if (["read", "edit", "write"].includes(tool)) {
				const p = args.filePath;
				if (p) envelope.paths = [p];
			} else if (tool === "grep") {
				// grep with no path searches the CWD — project that (#132).
				const p = args.path ?? ".";
				envelope.paths = [p];
			} else if (tool === "glob") {
				// Glob with brace expansion projects the base directory
				// before the braces so the engine evaluates the containing
				// path (#132).
				const p = args.path;
				if (p) {
					const braceIndex = p.indexOf("{");
					envelope.paths = [braceIndex > 0 ? p.slice(0, braceIndex) : p];
				} else {
					envelope.paths = ["."];
				}
			} else if (tool === "lsp") {
				const p = args.filePath;
				if (p) envelope.paths = [p];
			} else if (tool === "webfetch") {
				envelope.url = args.url;
			}
			const decision = callGuardrail(envelope);
			if (isPendingOperatorAction(decision)) {
				const message = `WebAuthn approval required for ${decision.operator_action}. Open ${decision.approval_url}`;
				if (client?.tui?.showToast) {
					try {
						await client.tui.showToast({
							body: { title: "Guardrail Approval Required", message, variant: "warning", duration: 15000 },
						});
					} catch {
						process.stderr.write(`${message}\n`);
					}
				}
				throw new Error(`guardrail: ${message}`);
			}
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
