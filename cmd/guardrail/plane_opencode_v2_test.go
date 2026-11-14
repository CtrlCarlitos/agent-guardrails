package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func useOpencodeMajor(t *testing.T, output string, probeErr bool) {
	t.Helper()
	restore := opencodeMajorProbe
	opencodeMajorProbe = func() (string, error) {
		if probeErr {
			return "", os.ErrNotExist
		}
		return output, nil
	}
	opencodeMajorCache = 0
	opencodeMajorResolved = false
	t.Cleanup(func() {
		opencodeMajorProbe = restore
		opencodeMajorCache = 0
		opencodeMajorResolved = false
	})
}

func opencodePlaneConfig(t *testing.T) map[string]any {
	t.Helper()
	path, err := planeConfigPath("opencode")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("opencode.json not written: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// On a detected V2 binary, enable writes the directory artifact
// (guardrail/index.js), the native plugins entry and the external_directory
// ask — and no V1 shapes at all.
func TestEnableOpencodeV2WritesDirectoryPluginAndNativePermissions(t *testing.T) {
	driftSandbox(t)
	useOpencodeMajor(t, "opencode v2.3.0\n", false)
	enableForDrift(t, "opencode")

	stateDir, err := planePluginDir()
	if err != nil {
		t.Fatal(err)
	}
	pluginDir := filepath.Join(stateDir, "guardrail")
	artifact := filepath.Join(pluginDir, "index.js")
	raw, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatalf("V2 directory artifact missing: %v", err)
	}
	if !strings.Contains(string(raw), "async function setup") || !strings.Contains(string(raw), "execute.before") {
		t.Fatal("V2 artifact does not carry the dual-major plugin source")
	}
	if _, err := os.Stat(filepath.Join(stateDir, "guardrail.js")); !os.IsNotExist(err) {
		t.Fatal("V1 single-file artifact must not be written for a detected V2 binary")
	}

	doc := opencodePlaneConfig(t)
	plugins, _ := doc["plugins"].([]any)
	if len(plugins) != 1 || plugins[0] != pluginDir {
		t.Fatalf("plugins = %#v, want [%s]", doc["plugins"], pluginDir)
	}
	perms, _ := doc["permissions"].([]any)
	if len(perms) != 1 {
		t.Fatalf("permissions = %#v, want the external_directory ask", doc["permissions"])
	}
	rule, _ := perms[0].(map[string]any)
	if rule["action"] != "external_directory" || rule["effect"] != "ask" {
		t.Fatalf("permission rule = %#v", rule)
	}
	if _, exists := doc["plugin"]; exists {
		t.Fatal("V1 plugin key written for a detected V2 binary")
	}
	if !planeIntegrationRegistered("opencode") {
		t.Fatal("V2 wiring must count as registered")
	}
	if state := planeStatusState("opencode"); !strings.Contains(state, "opencode 2") {
		t.Fatalf("status state = %q, want it to name the major", state)
	}
}

// The hard constraint: on a detected V1 binary nothing changes — single-file
// artifact, plugin key, no V2 shapes.
func TestEnableOpencodeV1KeepsSingleFileEntry(t *testing.T) {
	driftSandbox(t)
	useOpencodeMajor(t, "1.19.5\n", false)
	enableForDrift(t, "opencode")

	stateDir, err := planePluginDir()
	if err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(stateDir, "guardrail.js")
	raw, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("V1 artifact missing: %v", err)
	}
	if !strings.Contains(string(raw), "async function setup") {
		t.Fatal("V1 artifact must carry the dual-major source (it serves both majors)")
	}
	doc := opencodePlaneConfig(t)
	plugin, _ := doc["plugin"].([]any)
	if len(plugin) != 1 || plugin[0] != pluginPath {
		t.Fatalf("plugin = %#v, want [%s]", doc["plugin"], pluginPath)
	}
	if _, exists := doc["plugins"]; exists {
		t.Fatal("V2 plugins key written for a detected V1 binary")
	}
	if _, exists := doc["permissions"]; exists {
		t.Fatal("V2 permissions array written for a detected V1 binary")
	}
	if state := planeStatusState("opencode"); !strings.Contains(state, "opencode 1") {
		t.Fatalf("status state = %q, want it to name the major", state)
	}
}

// When the major cannot be detected, enable assumes V1 (today's behavior)
// and says so loudly.
func TestEnableOpencodeUnknownMajorAssumesV1WithNote(t *testing.T) {
	driftSandbox(t)
	useInstalledPlanes(t, "opencode")
	useOpencodeMajor(t, "", true)
	stubOperatorEnrolled(t, false)
	refuseSubmits(t)
	recordAudits(t)
	var out, errb strings.Builder
	if code := run([]string{"plane", "enable", "opencode"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit = %d, want 0 (bootstrap); stderr=%q", code, errb.String())
	}
	if !strings.Contains(errb.String(), "opencode major not detected") {
		t.Fatalf("stderr must carry the major assumption note: %q", errb.String())
	}
	stateDir, err := planePluginDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "guardrail.js")); err != nil {
		t.Fatal("unknown major must keep the V1 single-file artifact")
	}
	doc := opencodePlaneConfig(t)
	if _, exists := doc["plugin"]; !exists {
		t.Fatal("unknown major must keep the V1 plugin key")
	}
	if state := planeStatusState("opencode"); !strings.Contains(state, "major unknown") {
		t.Fatalf("status state = %q, want it to name the unknown major", state)
	}
}

// A machine that flipped majors holds the previous major's guardrail entry;
// re-enabling converges to the detected major's wiring.
func TestEnableOpencodeMajorFlipConverges(t *testing.T) {
	driftSandbox(t)
	useOpencodeMajor(t, "1.19.5\n", false)
	enableForDrift(t, "opencode")

	useOpencodeMajor(t, "opencode v2.3.0\n", false)
	if !planeHandlerDriftOrFatal(t, "opencode") {
		t.Fatal("a major flip must count as handler drift so setup re-enables")
	}
	enableForDrift(t, "opencode")
	doc := opencodePlaneConfig(t)
	if _, exists := doc["plugin"]; exists {
		t.Fatalf("V1 entry survived the flip to V2: %#v", doc["plugin"])
	}
	if plugins, _ := doc["plugins"].([]any); len(plugins) != 1 {
		t.Fatalf("plugins after flip = %#v", doc["plugins"])
	}
}

// The registered check is major-aware so `setup` reconciles a cross-major
// wiring instead of skipping it as consistent.
func TestOpencodeRegistrationIsMajorAware(t *testing.T) {
	path, err := planeConfigPath("opencode")
	if err != nil {
		t.Fatal(err)
	}
	stateDir, err := planePluginDir()
	if err != nil {
		t.Fatal(err)
	}
	v2Entry := filepath.Join(stateDir, "guardrail")
	v1Entry := filepath.Join(stateDir, "guardrail.js")

	useOpencodeMajor(t, "opencode v2.3.0\n", false)
	writePlaneSettings(t, path, `{"plugins":[`+quoteJSON(v2Entry)+`]}`)
	if !planeIntegrationRegistered("opencode") {
		t.Fatal("V2 entry must count as registered on a V2 binary")
	}
	writePlaneSettings(t, path, `{"plugin":[`+quoteJSON(v1Entry)+`]}`)
	if planeIntegrationRegistered("opencode") {
		t.Fatal("a V1 entry must NOT count as registered on a V2 binary (cross-major wiring)")
	}
	if state := planeStatusState("opencode"); !strings.Contains(state, "NOT registered") || !strings.Contains(state, "V1") {
		t.Fatalf("cross-major state = %q, want a loud NOT-registered naming V1", state)
	}

	// Unknown major accepts either shape so a missing binary cannot force a
	// re-enable loop.
	useOpencodeMajor(t, "", true)
	writePlaneSettings(t, path, `{"plugins":[`+quoteJSON(v2Entry)+`]}`)
	if !planeIntegrationRegistered("opencode") {
		t.Fatal("unknown major must accept either shape")
	}
	writePlaneSettings(t, path, `{"plugin":[`+quoteJSON(v1Entry)+`]}`)
	if !planeIntegrationRegistered("opencode") {
		t.Fatal("unknown major must accept either shape")
	}
}

func planeHandlerDriftOrFatal(t *testing.T, plane string) bool {
	t.Helper()
	drifted, err := planeHandlerDrift(plane)
	if err != nil {
		t.Fatal(err)
	}
	return drifted
}

func quoteJSON(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
