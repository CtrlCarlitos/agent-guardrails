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

// TestOpencodePluginBakesDegradedAllowTools pins the codegen surface: the
// engine-contract list replaces the placeholder, so the deployed artifact
// never carries a hand-curated tool set.
func TestOpencodePluginBakesDegradedAllowTools(t *testing.T) {
	source := string(OpencodePluginFor("/usr/local/bin/guardrail"))
	if strings.Contains(source, "__DEGRADED_ALLOW_TOOLS__") {
		t.Fatal("placeholder survived in baked plugin")
	}
	if !strings.Contains(source, `new Set(["question","todowrite"])`) {
		t.Fatalf("baked degraded-allow set missing:\n%s", source[:400])
	}
}

// TestOpencodePluginDegradedAllowOnTransportFailure pins the B+ valve: with
// the engine unspawnable, a communication tool (question) allows locally
// with a stderr notice, while everything else (read) still fails closed.
// The missing binary fails instantly with ENOENT, so no retry ladder runs.
func TestOpencodePluginDegradedAllowOnTransportFailure(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to exercise the embedded OpenCode plugin")
	}
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
let questionThrew = false;
try {
	await before({ tool: "question", sessionID: "s" }, { args: { question: "engine is down, are you there?" } });
} catch (e) { questionThrew = true; console.log("QUESTION_THREW: " + e.message); }
let readThrew = false;
try {
	await before({ tool: "read", sessionID: "s" }, { args: { filePath: "/repo/a.txt" } });
} catch (e) { readThrew = true; console.log("READ_THREW: " + e.message); }
console.log("DONE questionThrew=" + questionThrew + " readThrew=" + readThrew);
`
	var output bytes.Buffer
	cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("plugin runner failed: %v\n%s", err, output.String())
	}
	got := output.String()
	if !strings.Contains(got, "questionThrew=false") {
		t.Fatalf("question must degraded-allow on transport failure:\n%s", got)
	}
	if !strings.Contains(got, "readThrew=true") {
		t.Fatalf("read must fail closed on transport failure:\n%s", got)
	}
	if !strings.Contains(got, "[guardrail: engine unreachable; degraded allow for question") {
		t.Fatalf("stderr notice missing:\n%s", got)
	}
}

// TestOpencodePluginReachableEngineFailsClosedForCommunication pins the
// trigger boundary: a spawnable engine that returns garbage is a REACHABLE
// engine — question must fail closed, never degraded-allow. "engine
// unreachable" must not become an allow path.
func TestOpencodePluginReachableEngineFailsClosedForCommunication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake engine is a POSIX shell script")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to exercise the embedded OpenCode plugin")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "guardrail")
	fake := `#!/bin/sh
IFS= read -r _ || :
printf '%s' 'not-json'
`
	if err := os.WriteFile(binary, []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(dir, "guardrail.mjs")
	if err := os.WriteFile(pluginPath, OpencodePluginFor(binary), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.default({ directory: "/repo" });
const before = plugin["tool.execute.before"];
try {
	await before({ tool: "question", sessionID: "s" }, { args: { question: "reachable but broken" } });
	console.log("DONE allowed");
} catch (e) { console.log("DONE threw: " + e.message); }
`
	var output bytes.Buffer
	cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
	cmd.Stdout = &output
	cmd.Stderr = &output
	_ = cmd.Run()
	if !strings.Contains(output.String(), "DONE threw") {
		t.Fatalf("reachable-but-malformed engine must fail closed for question:\n%s", output.String())
	}
	if strings.Contains(output.String(), "degraded allow") {
		t.Fatalf("degraded allow fired for a reachable engine:\n%s", output.String())
	}
}
