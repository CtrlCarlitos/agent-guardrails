package genconfig

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// OpenCode on Windows logs a degraded allow for every real todowrite and
// question call (ETIMEDOUT at the 15 s probe), yet the same envelopes replayed
// through the installed hook answer in ~70 ms, and neither tool has ever
// reached the audit log. plugin-failures.log only says "timed out"; it cannot
// say where the time went, and a retried tool that stalls once and then
// succeeds leaves no trace at all. The timing trace records, per slow or
// failed call, each phase and attempt, so the next session shows whether only
// these tools stall, whether the process started, and how long each step took.
func TestOpencodePluginWritesTimingTraceForFailedCalls(t *testing.T) {
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
try { await before({ tool: "todowrite", sessionID: "s", callID: "c1" }, { args: { todos: [] } }); } catch {}
try { await before({ tool: "bash", sessionID: "s", callID: "c2" }, { args: { command: "ls" } }); } catch {}
`
	var output bytes.Buffer
	cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
	cmd.Stdout = &output
	cmd.Stderr = &output
	cmd.Env = testenv.ChildProcessEnv(testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: stateRoot})
	if err := cmd.Run(); err != nil {
		t.Fatalf("plugin runner failed: %v\n%s", err, output.String())
	}
	file, err := os.Open(filepath.Join(stateRoot, "guardrail", "plugin-timing.jsonl"))
	if err != nil {
		t.Fatalf("timing trace not written: %v\n%s", err, output.String())
	}
	defer file.Close()
	byTool := map[string]map[string]any{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var entry map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("trace line is not JSON: %q (%v)", scanner.Text(), err)
		}
		byTool[entry["tool"].(string)] = entry
	}
	for tool, wantAttempts := range map[string]int{"todowrite": 1, "bash": 3} {
		entry, ok := byTool[tool]
		if !ok {
			t.Fatalf("no trace for %s: %v", tool, byTool)
		}
		for _, key := range []string{"ts", "call_id", "runtime", "envelope_bytes", "total_ms", "daemon", "attempts", "result"} {
			if _, ok := entry[key]; !ok {
				t.Errorf("%s trace lacks %q: %v", tool, key, entry)
			}
		}
		attempts, _ := entry["attempts"].([]any)
		if len(attempts) != wantAttempts {
			t.Errorf("%s: %d attempts traced, want %d: %v", tool, len(attempts), wantAttempts, entry)
		}
		for _, a := range attempts {
			attempt := a.(map[string]any)
			for _, key := range []string{"ms", "timeout_ms", "outcome"} {
				if _, ok := attempt[key]; !ok {
					t.Errorf("%s attempt lacks %q: %v", tool, key, attempt)
				}
			}
			if !strings.Contains(attempt["outcome"].(string), "ENOENT") {
				t.Errorf("%s attempt outcome = %v, want the spawn error", tool, attempt["outcome"])
			}
		}
	}
	if got := byTool["todowrite"]["result"]; got != "degraded-allow" {
		t.Errorf("todowrite result = %v, want degraded-allow", got)
	}
	if got := byTool["bash"]["result"]; got != "fail-closed" {
		t.Errorf("bash result = %v, want fail-closed", got)
	}
}

// A fast answer writes nothing; a slow one writes one line even though it
// succeeded, which is the case plugin-failures.log never shows.
func TestOpencodePluginTimingTraceSkipsFastAndRecordsSlowCalls(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to exercise the embedded OpenCode plugin")
	}
	dir := t.TempDir()
	engine := writeOpencodeEngine(t, dir, "guardrail")
	pluginPath := filepath.Join(dir, "guardrail.mjs")
	if err := os.WriteFile(pluginPath, OpencodePluginFor(engine), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.default({ directory: "/repo" });
await plugin["tool.execute.before"]({ tool: "todowrite", sessionID: "s", callID: "c1" }, { args: { todos: [] } });
`
	run := func(sleepMS string) []string {
		t.Helper()
		stateRoot := t.TempDir()
		var output bytes.Buffer
		cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
		cmd.Stdout = &output
		cmd.Stderr = &output
		cmd.Env = append(testenv.ChildProcessEnv(testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: stateRoot}),
			opencodeHelperEnv+"=1", "GUARDRAIL_TEST_RESPONSE=allow", "GUARDRAIL_TEST_SLEEP_MS="+sleepMS)
		if err := cmd.Run(); err != nil {
			t.Fatalf("plugin runner failed: %v\n%s", err, output.String())
		}
		raw, err := os.ReadFile(filepath.Join(stateRoot, "guardrail", "plugin-timing.jsonl"))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	// The rule is "nothing under a second is written", not "this call is
	// fast": under the full suite a Windows spawn of the test binary took
	// 2.6 s, and logging it was correct.
	for _, line := range run("0") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		if entry["total_ms"].(float64) < 1000 {
			t.Errorf("a call under a second wrote a timing trace: %s", line)
		}
	}
	lines := run("1300")
	if len(lines) != 1 {
		t.Fatalf("a slow allow wrote %d trace lines, want 1: %v", len(lines), lines)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatal(err)
	}
	if entry["result"] != "engine" || entry["total_ms"].(float64) < 1000 {
		t.Errorf("slow trace = %v, want result engine and total_ms >= 1000", entry)
	}
	attempts := entry["attempts"].([]any)
	if len(attempts) != 1 || attempts[0].(map[string]any)["outcome"] != "exit 0" || attempts[0].(map[string]any)["pid"] == nil {
		t.Errorf("slow trace attempts = %v, want one exit 0 attempt with a pid", attempts)
	}
}
