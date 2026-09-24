package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/testenv"
)

// driftSandbox isolates every root the planes read and points the
// installedExecutable seam at an empty file A inside the sandbox. It returns
// A and a sibling path B for the "binary moved" case.
func driftSandbox(t *testing.T) (a, b string) {
	t.Helper()
	home := t.TempDir()
	testenv.SetHome(t, home)
	testenv.SetConfig(t, filepath.Join(home, ".config"))
	testenv.SetState(t, t.TempDir())
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	guardTestHome(t)

	bin := filepath.Join(home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	a = filepath.Join(bin, "guardrail-a")
	b = filepath.Join(bin, "guardrail-b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	useInstalledExecutable(t, a)
	return a, b
}

func useInstalledExecutable(t *testing.T, path string) {
	t.Helper()
	orig := installedExecutable
	installedExecutable = func() (string, error) { return path, nil }
	t.Cleanup(func() { installedExecutable = orig })
}

func assertDrift(t *testing.T, plane string, want bool) {
	t.Helper()
	got, err := planeHandlerDrift(plane)
	if err != nil {
		t.Fatalf("%s: planeHandlerDrift error: %v", plane, err)
	}
	if got != want {
		t.Fatalf("%s: planeHandlerDrift = %v, want %v", plane, got, want)
	}
}

func enableForDrift(t *testing.T, plane string) {
	t.Helper()
	if err := enablePlaneIntegration(plane); err != nil {
		t.Fatalf("%s: enable: %v", plane, err)
	}
}

func TestHandlerDriftFalseRightAfterEnable(t *testing.T) {
	for _, plane := range supportedPlanes {
		t.Run(plane, func(t *testing.T) {
			driftSandbox(t)
			enableForDrift(t, plane)
			assertDrift(t, plane, false)
		})
	}
}

func TestHandlerDriftTrueWhenBinaryPathChanged(t *testing.T) {
	for _, plane := range supportedPlanes {
		t.Run(plane, func(t *testing.T) {
			_, b := driftSandbox(t)
			enableForDrift(t, plane)
			useInstalledExecutable(t, b)
			assertDrift(t, plane, true)
		})
	}
}

func TestHandlerDriftIgnoresStrippedClaudeIDs(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "claude")
	path, err := planeConfigPath("claude")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := genconfig.ReadJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	hooks, _ := doc["hooks"].(map[string]any)
	stripped := 0
	for _, ev := range hooks {
		groups, _ := ev.([]any)
		for _, g := range groups {
			if m, ok := g.(map[string]any); ok {
				if _, has := m["id"]; has {
					delete(m, "id")
					stripped++
				}
			}
		}
	}
	if stripped == 0 {
		t.Fatal("enable wrote no hook group ids to strip")
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writePlaneSettings(t, path, string(raw))
	assertDrift(t, "claude", false)
}

func codexWrapperPath(t *testing.T) string {
	t.Helper()
	path, err := planeConfigPath("codex")
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(filepath.Dir(path), "guardrail-hook.cmd")
}

func TestHandlerDriftTrueWhenCodexWrapperMissing(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "codex")
	if err := os.Remove(codexWrapperPath(t)); err != nil {
		t.Fatal(err)
	}
	assertDrift(t, "codex", true)
}

func TestHandlerDriftTrueWhenCodexWrapperStale(t *testing.T) {
	driftSandbox(t)
	enableForDrift(t, "codex")
	if err := os.WriteFile(codexWrapperPath(t), genconfig.CodexWrapperContent("C:\\elsewhere\\guardrail.exe"), 0o700); err != nil {
		t.Fatal(err)
	}
	assertDrift(t, "codex", true)
}

func TestHandlerDriftTrueWhenOpencodePluginStale(t *testing.T) {
	_, b := driftSandbox(t)
	enableForDrift(t, "opencode")
	dir, err := planePluginDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "guardrail.js"), genconfig.OpencodePluginFor(b), 0o644); err != nil {
		t.Fatal(err)
	}
	assertDrift(t, "opencode", true)
}

func TestHandlerDriftFalseWhenSettingsMissing(t *testing.T) {
	for _, plane := range supportedPlanes {
		t.Run(plane, func(t *testing.T) {
			driftSandbox(t)
			path, err := planeConfigPath(plane)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("sandbox already has %s: %v", path, err)
			}
			assertDrift(t, plane, false)
		})
	}
}

func TestHandlerDriftErrorsOnUnparseableSettings(t *testing.T) {
	driftSandbox(t)
	path, err := planeConfigPath("claude")
	if err != nil {
		t.Fatal(err)
	}
	writePlaneSettings(t, path, "{not json")
	if _, err := planeHandlerDrift("claude"); err == nil {
		t.Fatal("unparseable claude settings produced no error")
	}
}

// mutateFirstOwnedGroup rewrites the plane's settings after applying mutate
// to the first hook group that planeHandlerDrift treats as Guardrail-owned.
func mutateFirstOwnedGroup(t *testing.T, plane string, mutate func(group map[string]any)) {
	t.Helper()
	path, err := planeConfigPath(plane)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := genconfig.ReadJSONObject(path)
	if err != nil {
		t.Fatal(err)
	}
	key, owned := "hooks", claimedBy("guardrail-", "hook "+plane)
	switch plane {
	case "antigravity":
		key = "guardrail"
	case "codex":
		owned = claimedBy("guardrail-codex-", "")
	}
	events, _ := doc[key].(map[string]any)
	names := make([]string, 0, len(events))
	for name := range events {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		groups, _ := events[name].([]any)
		for _, g := range groups {
			if m, ok := g.(map[string]any); ok && owned(m) {
				mutate(m)
				raw, err := json.MarshalIndent(doc, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				writePlaneSettings(t, path, string(raw))
				return
			}
		}
	}
	t.Fatalf("%s: no owned hook group to mutate", plane)
}

var groupPlanes = []string{"claude", "antigravity", "codex"}

func TestHandlerDriftTrueWhenMatcherChanged(t *testing.T) {
	for _, plane := range groupPlanes {
		t.Run(plane, func(t *testing.T) {
			driftSandbox(t)
			enableForDrift(t, plane)
			mutateFirstOwnedGroup(t, plane, func(g map[string]any) { g["matcher"] = "SomethingElse" })
			assertDrift(t, plane, true)
		})
	}
}

func TestHandlerDriftTrueWhenTimeoutChanged(t *testing.T) {
	for _, plane := range groupPlanes {
		t.Run(plane, func(t *testing.T) {
			driftSandbox(t)
			enableForDrift(t, plane)
			mutateFirstOwnedGroup(t, plane, func(g map[string]any) {
				handlers, _ := g["hooks"].([]any)
				h, _ := handlers[0].(map[string]any)
				h["timeout"] = 9999
			})
			assertDrift(t, plane, true)
		})
	}
}
