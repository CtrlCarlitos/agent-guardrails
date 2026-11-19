package genconfig

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// On 2026-11-19 (live session, opencode v2.3.2, guardrail v0.23.45-dev) one
// edit of a two-edit parallel batch was denied capability-input-missing: the
// envelope reached the engine with tool=edit but no paths, meaning
// event.input carried neither path nor filePath. The handler reads tool and
// input synchronously from the same event object and buildEnvelope is pure,
// so the plugin cannot lose one without the other — unless concurrent
// invocations cross-talk. This test pins that boundary: concurrent
// execute.before pairs must each deliver their own envelope with their own
// paths, never an empty or swapped argument set. While it passes, an
// empty-input deny is host-delivered (upstream); if it ever fails, the
// race is ours.
func TestOpencodePluginV2ConcurrentEditsKeepTheirOwnPaths(t *testing.T) {
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
let hooks = {};
const ctx = {
  location: { directory: "/repo" },
  tool: { hook: async (name, cb) => { hooks[name] = cb; } },
  event: { subscribe: async function* () {} },
};
await loaded.default.setup(ctx);
if (!hooks["execute.before"]) throw new Error("execute.before not registered");

// Twenty pairs, both members of each pair dispatched without awaiting the
// other — the opencode host fires batched tool calls the same way. Large
// payloads match the live incident (its denied edit carried ~1.5KiB of
// oldString/newString).
const filler = "x".repeat(1536);
const fire = (ev) => hooks["execute.before"](ev);
const pair = (i) => Promise.all([
  fire({ tool: "edit", input: { path: "/repo/a" + i + ".md", oldString: filler, newString: filler }, sessionID: "ses_race", id: "call_a" + i, agent: "build", messageID: "m" + i }),
  fire({ tool: "edit", input: { path: "/repo/b" + i + ".md", oldString: filler, newString: filler }, sessionID: "ses_race", id: "call_b" + i, agent: "build", messageID: "m" + i }),
]);
await Promise.all(Array.from({ length: 20 }, (_, i) => pair(i)));
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
	seen := map[string]bool{}
	for _, env := range envelopes {
		callID, _ := env["call_id"].(string)
		if callID == "" {
			t.Fatalf("envelope without call_id: %#v", env)
		}
		if seen[callID] {
			t.Fatalf("call_id %s evaluated more than once", callID)
		}
		seen[callID] = true
		if env["tool"] != "edit" {
			t.Fatalf("call %s tool = %#v, want edit", callID, env["tool"])
		}
		paths, _ := env["paths"].([]any)
		if len(paths) != 1 {
			t.Fatalf("call %s reached the engine with paths=%#v — the live incident shape (capability-input-missing): %#v", callID, env["paths"], env)
		}
		got, _ := paths[0].(string)
		var expected string
		if strings.HasPrefix(callID, "call_a") {
			expected = "/repo/a" + strings.TrimPrefix(callID, "call_a") + ".md"
		} else {
			expected = "/repo/b" + strings.TrimPrefix(callID, "call_b") + ".md"
		}
		if got != expected {
			t.Fatalf("call %s paths=%q, want its own input path %q (cross-talk)", callID, got, expected)
		}
	}
	if len(seen) != 40 {
		t.Fatalf("captured %d distinct calls, want 40 (20 pairs)", len(seen))
	}
}
