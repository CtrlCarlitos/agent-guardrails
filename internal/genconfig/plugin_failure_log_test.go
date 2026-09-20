package genconfig

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestOpencodePluginLeavesFailureTrail pins the diagnostics half of degraded
// mode: engine-down events write no engine audit records (the engine never
// ran), so the plugin leaves its own greppable trail — one line per degraded
// allow and one per fail-closed transport failure — under the platform state
// root, where the runbook points the operator.
func TestOpencodePluginLeavesFailureTrail(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to exercise the embedded OpenCode plugin")
	}
	stateRoot := t.TempDir()
	dir := t.TempDir()
	deadBinary := filepath.Join(dir, "guardrail-does-not-exist")
	pluginPath := filepath.Join(dir, "guardrail.mjs")
	if err := os.WriteFile(pluginPath, OpencodePluginFor(deadBinary), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.default({ directory: "/repo" });
const before = plugin["tool.execute.before"];
try { await before({ tool: "question", sessionID: "s" }, { args: {} }); } catch {}
try { await before({ tool: "read", sessionID: "s" }, { args: { filePath: "/repo/a.txt" } }); } catch {}
`
	var output bytes.Buffer
	cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.Env = append(os.Environ(), "XDG_STATE_HOME="+stateRoot)
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "LOCALAPPDATA="+stateRoot)
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("plugin runner failed: %v\n%s", err, output.String())
	}
	raw, err := os.ReadFile(filepath.Join(stateRoot, "guardrail", "plugin-failures.log"))
	if err != nil {
		t.Fatalf("failure log not written: %v\n%s", err, output.String())
	}
	log := string(raw)
	if !strings.Contains(log, "degraded-allow tool=question") {
		t.Fatalf("degraded-allow line missing:\n%s", log)
	}
	if !strings.Contains(log, "engine-unreachable tool=read") {
		t.Fatalf("engine-unreachable line missing:\n%s", log)
	}
}
