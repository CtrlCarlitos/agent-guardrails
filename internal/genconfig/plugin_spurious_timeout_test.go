package genconfig

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// #452: the #427 timing trace from a real OpenCode session on Windows
// (bun 1.3.14) showed 115 of 117 logged calls failing their first spawn with
// ETIMEDOUT after 3-93 ms against a 15 s timeout: a process was created, no
// output, and the next attempt answered in ~120 ms. No attempt ever timed out
// for real. Retried tools paid ~640 ms per call for it; todowrite and question,
// with one attempt, degraded-allowed every time and never reached the audit
// log. An ETIMEDOUT far inside its budget is not a timeout: retry it once,
// at once.
func TestOpencodePluginRetriesASpuriousFastTimeoutOnce(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to exercise the embedded OpenCode plugin")
	}
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "guardrail.mjs")
	if err := os.WriteFile(pluginPath, OpencodePluginFor(filepath.Join(dir, "guardrail")), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := `
import { pathToFileURL } from "node:url";
const mode = process.argv[2];
let calls = 0;
globalThis.__GUARDRAIL_TEST_SPAWN__ = () => {
	calls++;
	const spurious = { pid: 100 + calls, stdout: "", stderr: "", status: null, signal: "SIGTERM", error: Object.assign(new Error("spawnSync guardrail ETIMEDOUT"), { code: "ETIMEDOUT" }) };
	if (mode === "always" || calls === 1) return spurious;
	return { pid: 100 + calls, stdout: '{"decision":"allow","reason":""}', stderr: "", status: 0, signal: null };
};
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.default({ directory: "/repo" });
const before = plugin["tool.execute.before"];
for (const tool of ["todowrite", "bash"]) {
	calls = 0;
	const t = Date.now();
	let threw = "";
	try { await before({ tool, sessionID: "s", callID: "c-" + tool }, { args: tool === "bash" ? { command: "ls" } : { todos: [] } }); } catch (e) { threw = e.message; }
	console.log("RESULT " + tool + " calls=" + calls + " ms=" + (Date.now() - t) + " threw=" + JSON.stringify(threw));
}
`
	run := func(mode string) string {
		var output bytes.Buffer
		cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath, mode)
		cmd.Stdout = &output
		cmd.Stderr = &output
		cmd.Env = testenv.ChildProcessEnv(testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: t.TempDir()})
		if err := cmd.Run(); err != nil {
			t.Fatalf("plugin runner failed: %v\n%s", err, output.String())
		}
		return output.String()
	}

	got := run("once")
	if strings.Contains(got, "degraded allow for todowrite") {
		t.Errorf("a spurious fast timeout still degraded todowrite:\n%s", got)
	}
	for _, want := range []string{`RESULT todowrite calls=2`, `RESULT bash calls=2`} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q (one immediate retry):\n%s", want, got)
		}
	}
	// No 500 ms backoff before the immediate retry.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "RESULT bash") {
			var calls, ms int
			if _, err := fmtSscanf(line, &calls, &ms); err == nil && ms >= 400 {
				t.Errorf("bash waited %d ms before the immediate retry: %s", ms, line)
			}
		}
	}

	// A fast timeout that repeats is a real failure: todowrite degrades as
	// before, bash still fails closed; the retry is once, not a loop.
	got = run("always")
	if !strings.Contains(got, "degraded allow for todowrite") {
		t.Errorf("a repeating fast timeout must still degrade todowrite:\n%s", got)
	}
	if !strings.Contains(got, `RESULT todowrite calls=2`) {
		t.Errorf("todowrite must try exactly twice:\n%s", got)
	}
	if !strings.Contains(got, `RESULT bash`) || !strings.Contains(got, "failing closed") {
		t.Errorf("bash must still fail closed:\n%s", got)
	}
}

func fmtSscanf(line string, calls, ms *int) (int, error) {
	var tool, threw string
	return fmt.Sscanf(line, "RESULT %s calls=%d ms=%d threw=%s", &tool, calls, ms, &threw)
}
