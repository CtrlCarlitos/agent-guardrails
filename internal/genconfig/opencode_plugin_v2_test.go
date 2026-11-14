package genconfig

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// The dual-major contract (#534, ADR-0034): V1 loads the named export
// GuardrailPlugin (and default.server), V2 reads default.id/default.setup.
// setup() registers ctx.tool.hook("execute.before") and normalizes the V2
// event into the ADR-0007 wire envelope, translating V2's native tool names
// (shell/patch/subagent) and arg spellings (path, not filePath) onto the
// V1-native names the engine contract already knows.
func TestOpencodePluginV2EntrypointsAndHook(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to exercise the embedded OpenCode plugin")
	}
	dir := t.TempDir()
	engine := writeOpencodeEngine(t, dir, "guardrail")
	capture := filepath.Join(dir, "envelopes.jsonl")
	pluginPath := filepath.Join(dir, "guardrail.mjs")
	if err := os.WriteFile(pluginPath, OpencodePluginFor(engine), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const def = loaded.default;
if (!def || def.id !== "guardrail") throw new Error("default.id is not guardrail: " + def?.id);
if (typeof def.server !== "function") throw new Error("default.server is not a function");
if (typeof def.setup !== "function") throw new Error("default.setup is not a function");
if (typeof loaded.GuardrailPlugin !== "function") throw new Error("named export GuardrailPlugin missing");

// V1 (>= 1.18.18) has been observed to invoke default.setup with a V1-shaped
// ctx; setup must return quietly rather than throw.
await def.setup({});
await def.setup(undefined);

let hooks = {};
const events = [];
const ctx = {
  location: { directory: "/repo" },
  tool: { hook: async (name, cb) => { hooks[name] = cb; } },
  event: { subscribe: async function* () { for (const e of events) yield e; } },
};
await def.setup(ctx);
if (!hooks["execute.before"]) throw new Error("execute.before not registered");

async function fire(ev) {
  try { await hooks["execute.before"](ev); return "allowed"; }
  catch (e) { return "threw: " + e.message; }
}
// deny: engine says deny, plugin must throw (throw-to-block preserved).
console.log("SHELL=" + await fire({ tool: "shell", input: { command: "rm -rf /" }, sessionID: "ses_1", id: "call_1", agent: "build", messageID: "msg_1" }));
// allow: engine says allow, hook returns normally.
console.log("READ=" + await fire({ tool: "read", input: { path: "/repo/a.txt" }, sessionID: "ses_1", id: "call_2", agent: "build", messageID: "msg_2" }));
// unknown V2 tool: envelope still evaluated, never crashes the plugin.
console.log("NEWTOOL=" + await fire({ tool: "experimental_image_generate", input: { prompt: "x" }, sessionID: "ses_1", id: "call_3", agent: "build", messageID: "msg_3" }));
`
	var output strings.Builder
	cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.Env = append(testenv.ChildProcessEnv(testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}),
		"GO_WANT_OPENCODE_ENGINE_HELPER=1", "GUARDRAIL_TEST_RESPONSE=deny", "GUARDRAIL_TEST_CAPTURE="+capture)
	if err := cmd.Run(); err != nil {
		t.Fatalf("plugin runner failed: %v\n%s", err, output.String())
	}
	got := output.String()
	if !strings.Contains(got, "SHELL=threw: guardrail:") {
		t.Fatalf("shell deny must throw on V2:\n%s", got)
	}
	if !strings.Contains(got, "READ=allowed") && !strings.Contains(got, "READ=threw") {
		// deny response applies to every call; READ may throw too. The shell
		// assertion above is the throw contract; here only non-crash matters.
		t.Fatalf("read must not crash the hook:\n%s", got)
	}
	if !strings.Contains(got, "NEWTOOL=allowed") && !strings.Contains(got, "NEWTOOL=threw: guardrail:") {
		t.Fatalf("unknown V2 tool must evaluate through the engine, not crash:\n%s", got)
	}

	envelopes := readCapture(t, capture)
	if len(envelopes) < 3 {
		t.Fatalf("capture has %d envelopes, want >= 3:\n%s", len(envelopes), got)
	}
	shell := findEnvelope(t, envelopes, "call_1")
	if shell["tool"] != "bash" {
		t.Fatalf("V2 shell must reach the engine as the contract name bash: %v", shell["tool"])
	}
	if shell["command"] != "rm -rf /" || shell["session_id"] != "ses_1" || shell["cwd"] != "/repo" || shell["event"] != "pre" {
		t.Fatalf("shell envelope = %#v", shell)
	}
	read := findEnvelope(t, envelopes, "call_2")
	if read["tool"] != "read" {
		t.Fatalf("read tool = %v", read["tool"])
	}
	paths, _ := read["paths"].([]any)
	if len(paths) != 1 || paths[0] != "/repo/a.txt" {
		t.Fatalf("read paths = %#v (V2 spells the arg path, not filePath)", read["paths"])
	}
}

// ADR-0015 on V2: permission.asked carries the tool callID in source.id;
// permission.replied{requestID, reply} correlates back. An approved callID
// is consumed exactly once by the matching execute.before.
func TestOpencodePluginV2HostApprovalCorrelation(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to exercise the embedded OpenCode plugin")
	}
	dir := t.TempDir()
	engine := writeOpencodeEngine(t, dir, "guardrail")
	capture := filepath.Join(dir, "envelopes.jsonl")
	pluginPath := filepath.Join(dir, "guardrail.mjs")
	if err := os.WriteFile(pluginPath, OpencodePluginFor(engine), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const events = [
  { type: "permission.asked", id: "per_1", sessionID: "ses_1", action: "read", resources: ["/repo/a.txt"], source: { type: "tool", messageID: "msg_1", id: "call_9" } },
  { type: "permission.replied", sessionID: "ses_1", requestID: "per_1", reply: "once" },
  { type: "permission.replied", sessionID: "ses_1", requestID: "per_404", reply: "once" },
];
let hooks = {};
const ctx = {
  location: { directory: "/repo" },
  tool: { hook: async (name, cb) => { hooks[name] = cb; } },
  event: { subscribe: async function* () { for (const e of events) yield e; } },
};
await loaded.default.setup(ctx);
await new Promise((r) => setTimeout(r, 20));
await hooks["execute.before"]({ tool: "read", input: { path: "/repo/a.txt" }, sessionID: "ses_1", id: "call_9", agent: "build", messageID: "msg_1" }).catch(() => {});
await hooks["execute.before"]({ tool: "read", input: { path: "/repo/a.txt" }, sessionID: "ses_1", id: "call_9", agent: "build", messageID: "msg_1" }).catch(() => {});
console.log("DONE");
`
	var output strings.Builder
	cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.Env = append(testenv.ChildProcessEnv(testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()}),
		"GO_WANT_OPENCODE_ENGINE_HELPER=1", "GUARDRAIL_TEST_RESPONSE=allow", "GUARDRAIL_TEST_CAPTURE="+capture)
	if err := cmd.Run(); err != nil {
		t.Fatalf("plugin runner failed: %v\n%s", err, output.String())
	}
	envelopes := readCapture(t, capture)
	if len(envelopes) != 2 {
		t.Fatalf("want 2 envelopes, got %d:\n%s", len(envelopes), output.String())
	}
	first := findEnvelope(t, envelopes, "call_9")
	if first["host_approved"] != true {
		t.Fatalf("approved callID must carry host_approved on its first use: %#v", first)
	}
	second := envelopes[1]
	if second["host_approved"] == true {
		t.Fatal("host approval must be consumed exactly once")
	}
}

func readCapture(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("envelope capture missing: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var env map[string]any
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			t.Fatalf("capture line not JSON: %q", line)
		}
		out = append(out, env)
	}
	return out
}

func findEnvelope(t *testing.T, envelopes []map[string]any, callID string) map[string]any {
	t.Helper()
	for _, env := range envelopes {
		if env["call_id"] == callID {
			return env
		}
	}
	t.Fatalf("no envelope for call_id %s in %#v", callID, envelopes)
	return nil
}
