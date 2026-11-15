package genconfig

import (
	"encoding/json"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpencodeTimingOptInSuccessfulAndBounded(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node required")
	}
	for _, opt := range []string{"", "1"} {
		t.Run("opt="+opt, func(t *testing.T) {
			dir, state := t.TempDir(), t.TempDir()
			plugin := filepath.Join(dir, "plugin.mjs")
			if err := os.WriteFile(plugin, OpencodePluginFor(filepath.Join(dir, "unused")), 0600); err != nil {
				t.Fatal(err)
			}
			runner := `
import {pathToFileURL} from 'node:url';
import {readFileSync} from 'node:fs';
globalThis.__GUARDRAIL_TEST_SPAWN__ = () => ({pid:1,stdout:'{"decision":"allow"}',stderr:'',status:0});
const loaded=await import(pathToFileURL(process.argv[1]).href);
const hooks=await loaded.GuardrailPlugin({directory:'/repo'});
for(let i=0;i<205;i++) {
 await hooks['tool.execute.before']({tool:'read',sessionID:'timing-s',callID:'call-'+i},{args:{filePath:'/repo/README.md'}});
 if(i===0 && process.env.GUARDRAIL_TIMING==='1') {
 const rows=readFileSync(process.env.GUARDRAIL_TEST_TIMING_PATH,'utf8').trim().split('\n');
 if(rows.length!==1) throw new Error('oversized or invalid history retained');
 }
}
`
			if opt == "1" {
				path := filepath.Join(state, "guardrail", "plugin-timing.jsonl")
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(strings.Repeat("x", 5000)+"\nnot-json\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(node, "--input-type=module", "--eval", runner, plugin)
			cmd.Env = append(testenv.ChildProcessEnv(testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: state}), "GUARDRAIL_TIMING="+opt, "GUARDRAIL_TEST_TIMING_PATH="+filepath.Join(state, "guardrail", "plugin-timing.jsonl"))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			path := filepath.Join(state, "guardrail", "plugin-timing.jsonl")
			raw, err := os.ReadFile(path)
			if opt == "" {
				if !os.IsNotExist(err) {
					t.Fatalf("default wrote timing: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if len(lines) != 200 {
				t.Fatalf("samples=%d, want last 200", len(lines))
			}
			var sample map[string]any
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &sample); err != nil {
				t.Fatal(err)
			}
			if sample["call_id"] != "call-204" || sample["session_id"] != "timing-s" || sample["host"] != "opencode" || sample["transport"] != "spawn" {
				t.Errorf("metadata: %v", sample)
			}
			phases, ok := sample["phases"].(map[string]any)
			if !ok {
				t.Fatalf("no phases: %v", sample)
			}
			for _, key := range []string{"wrapper_dispatch_ms", "daemon_dial_ms", "spawn_attempt_1_ms"} {
				if phases[key] == nil {
					t.Errorf("missing %s: %v", key, sample)
				}
			}
			if phases["host_dispatch_ms"] != nil {
				t.Errorf("host dispatch inferred: %v", sample)
			}
		})
	}
}

func TestOpencodeTimingDefaultDoesNotTraceFailures(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node required")
	}
	dir, state := t.TempDir(), t.TempDir()
	plugin := filepath.Join(dir, "plugin.mjs")
	if err := os.WriteFile(plugin, OpencodePluginFor(filepath.Join(dir, "missing")), 0600); err != nil {
		t.Fatal(err)
	}
	runner := `import {pathToFileURL} from 'node:url';const p=await import(pathToFileURL(process.argv[1]).href);const h=await p.GuardrailPlugin({directory:'/repo'});try{await h['tool.execute.before']({tool:'todowrite',sessionID:'s',callID:'c'},{args:{todos:[]}})}catch{}`
	cmd := exec.Command(node, "--input-type=module", "--eval", runner, plugin)
	cmd.Env = append(testenv.ChildProcessEnv(testenv.Roots{Home: t.TempDir(), Config: t.TempDir(), State: state}), "GUARDRAIL_TIMING=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(state, "guardrail", "plugin-timing.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("default failure emitted timing: %v", err)
	}
}
