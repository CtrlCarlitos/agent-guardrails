package genconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestOpencodeConfigV2FragmentShape(t *testing.T) {
	frag := OpencodeConfigV2("/state/guardrail")
	plugins, ok := frag["plugins"].([]string)
	if !ok || len(plugins) != 1 || plugins[0] != "/state/guardrail" {
		t.Fatalf("plugins entry = %#v, want [/state/guardrail]", frag["plugins"])
	}
	want := []any{
		map[string]any{"action": "external_directory", "resource": "*", "effect": "ask"},
	}
	if got, ok := frag["permissions"].([]any); !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("permissions = %#v, want %#v", frag["permissions"], want)
	}
	if _, exists := frag["permission"]; exists {
		t.Fatal("V2 fragment must not carry the V1 permission object")
	}
	if _, exists := frag["plugin"]; exists {
		t.Fatal("V2 fragment must not carry the V1 plugin key")
	}
}

// The external_directory ask restores the host default V1 had (V2 allows by
// default); it is the only permissions entry guardrail emits on V2.
func TestOpencodeV2ExternalDirectoryRule(t *testing.T) {
	rules := OpencodeV2PermissionRules()
	if len(rules) != 1 {
		t.Fatalf("OpencodeV2PermissionRules has %d rules, want 1", len(rules))
	}
	rule, ok := rules[0].(map[string]any)
	if !ok || rule["action"] != "external_directory" || rule["resource"] != "*" || rule["effect"] != "ask" {
		t.Fatalf("rule = %#v, want external_directory * ask", rules[0])
	}
}

func writeOpencodeDoc(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "opencode.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readDoc(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestMergeOpencodeV2KeepsOperatorPluginsAndAddsGuardrail(t *testing.T) {
	path := writeOpencodeDoc(t, `{"plugins":["/opt/acme"],"theme":"dark"}`)
	if err := MergePlaneInto(path, "opencode", OpencodeConfigV2("/state/guardrail")); err != nil {
		t.Fatal(err)
	}
	doc := readDoc(t, path)
	plugins, ok := doc["plugins"].([]any)
	if !ok || len(plugins) != 2 {
		t.Fatalf("plugins = %#v, want acme then guardrail", doc["plugins"])
	}
	if plugins[0] != "/opt/acme" || plugins[1] != "/state/guardrail" {
		t.Fatalf("plugins = %#v", plugins)
	}
	if doc["theme"] != "dark" {
		t.Fatal("unrelated settings must survive")
	}
}

func TestMergeOpencodeV2IsIdempotent(t *testing.T) {
	path := writeOpencodeDoc(t, `{}`)
	for i := 0; i < 2; i++ {
		if err := MergePlaneInto(path, "opencode", OpencodeConfigV2("/state/guardrail")); err != nil {
			t.Fatal(err)
		}
	}
	doc := readDoc(t, path)
	if plugins, _ := doc["plugins"].([]any); len(plugins) != 1 {
		t.Fatalf("second merge duplicated the plugins entry: %#v", doc["plugins"])
	}
	if perms, _ := doc["permissions"].([]any); len(perms) != 1 {
		t.Fatalf("second merge duplicated the permissions entry: %#v", doc["permissions"])
	}
}

// A machine that flipped majors holds the other major's guardrail entry; a
// merge must converge guardrail's own entries to the incoming fragment's
// shape. The operator's own entry under the retired key is theirs and
// survives (manifest discipline: never touch what guardrail did not write).
func TestMergeOpencodeV2AbsorbsLegacyV1PluginEntry(t *testing.T) {
	path := writeOpencodeDoc(t, `{"plugin":["/state/guardrail.js","/opt/acme-v1"]}`)
	if err := MergePlaneInto(path, "opencode", OpencodeConfigV2("/state/guardrail")); err != nil {
		t.Fatal(err)
	}
	doc := readDoc(t, path)
	plugin, _ := doc["plugin"].([]any)
	if len(plugin) != 1 || plugin[0] != "/opt/acme-v1" {
		t.Fatalf("operator's own V1-era plugin entry was touched: %#v", doc["plugin"])
	}
	plugins, _ := doc["plugins"].([]any)
	if len(plugins) != 1 || plugins[0] != "/state/guardrail" {
		t.Fatalf("plugins = %#v", doc["plugins"])
	}
}

func TestMergeOpencodeV1AbsorbsV2PluginsEntry(t *testing.T) {
	path := writeOpencodeDoc(t, `{"plugins":["/state/guardrail","/opt/acme"]}`)
	if err := MergePlaneInto(path, "opencode", OpencodeConfig(nil, "/state/guardrail.js")); err != nil {
		t.Fatal(err)
	}
	doc := readDoc(t, path)
	plugins, _ := doc["plugins"].([]any)
	if len(plugins) != 1 || plugins[0] != "/opt/acme" {
		t.Fatalf("operator's own V2-era plugins entry was touched: %#v", doc["plugins"])
	}
	plugin, _ := doc["plugin"].([]any)
	if len(plugin) != 1 || plugin[0] != "/state/guardrail.js" {
		t.Fatalf("plugin = %#v", doc["plugin"])
	}
}

// The operator owns their permissions array: guardrail adds its
// external_directory ask only when the file has no rule for that action, and
// never reorders or overrides rules it did not write.
func TestMergeOpencodeV2SkipsExternalDirectoryWhenOperatorRules(t *testing.T) {
	path := writeOpencodeDoc(t, `{"permissions":[{"action":"external_directory","resource":"~/projects/*","effect":"allow"}]}`)
	if err := MergePlaneInto(path, "opencode", OpencodeConfigV2("/state/guardrail")); err != nil {
		t.Fatal(err)
	}
	perms, _ := readDoc(t, path)["permissions"].([]any)
	if len(perms) != 1 {
		t.Fatalf("guardrail added a rule beside the operator's own: %#v", perms)
	}
}

func TestMergeOpencodeV2AppendsAskWhenOperatorHasOtherRules(t *testing.T) {
	path := writeOpencodeDoc(t, `{"permissions":[{"action":"shell","resource":"git push *","effect":"ask"}]}`)
	if err := MergePlaneInto(path, "opencode", OpencodeConfigV2("/state/guardrail")); err != nil {
		t.Fatal(err)
	}
	perms, _ := readDoc(t, path)["permissions"].([]any)
	if len(perms) != 2 {
		t.Fatalf("permissions = %#v, want the operator rule plus guardrail's ask", perms)
	}
	if perms[0].(map[string]any)["action"] != "shell" {
		t.Fatal("operator rule must keep its position")
	}
}

func TestManifestRecordsOpencodeV2Entries(t *testing.T) {
	manifestEnv(t)
	path := writeOpencodeDoc(t, `{"plugins":["/opt/acme"]}`)
	if err := MergePlaneInto(path, "opencode", OpencodeConfigV2("/state/guardrail")); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest("opencode")
	if err != nil || m == nil {
		t.Fatalf("manifest not written: %v", err)
	}
	var kinds []string
	for _, entry := range m.Entries {
		kinds = append(kinds, manifestKind(entry.Path)+":"+joinPath(entry.Path))
	}
	joined := strings.Join(kinds, ",")
	if !strings.Contains(joined, "plugin:plugins") {
		t.Fatalf("plugins entry not recorded as plugin kind: %s", joined)
	}
	if !strings.Contains(joined, "permission:permissions") {
		t.Fatalf("permissions entry not recorded as permission kind: %s", joined)
	}
}

func TestRemovePlaneRestoresOperatorStateAfterV2Merge(t *testing.T) {
	manifestEnv(t)
	path := writeOpencodeDoc(t, `{"plugins":["/opt/acme"],"permissions":[{"action":"shell","resource":"git push *","effect":"ask"}],"theme":"dark"}`)
	if err := MergePlaneInto(path, "opencode", OpencodeConfigV2("/state/guardrail")); err != nil {
		t.Fatal(err)
	}
	report, err := RemovePlaneFromReporting(path, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if report.Removed != 2 {
		t.Fatalf("removed %d entries, want 2 (plugins + permissions)", report.Removed)
	}
	if report.Fallback {
		t.Fatal("removal should have used the manifest")
	}
	want := map[string]any{
		"plugins":     []any{"/opt/acme"},
		"permissions": []any{map[string]any{"action": "shell", "resource": "git push *", "effect": "ask"}},
		"theme":       "dark",
	}
	if got := readDoc(t, path); !reflect.DeepEqual(got, want) {
		t.Fatalf("post-removal doc = %#v, want %#v", got, want)
	}
}

// No manifest (state cleared): the fallback still removes exactly the
// generated V2 entries and leaves the operator's alone.
func TestRemovePlaneFallbackRemovesV2Entries(t *testing.T) {
	manifestEnv(t)
	path := writeOpencodeDoc(t, `{"plugins":["/opt/acme","/state/guardrail"],"permissions":[{"action":"external_directory","resource":"*","effect":"ask"},{"action":"shell","resource":"git push *","effect":"ask"}]}`)
	report, err := RemovePlaneFromReporting(path, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Fallback {
		t.Fatal("removal with no manifest should report fallback")
	}
	doc := readDoc(t, path)
	plugins, _ := doc["plugins"].([]any)
	if len(plugins) != 1 || plugins[0] != "/opt/acme" {
		t.Fatalf("plugins after fallback removal = %#v", plugins)
	}
	perms, _ := doc["permissions"].([]any)
	if len(perms) != 1 || perms[0].(map[string]any)["action"] != "shell" {
		t.Fatalf("permissions after fallback removal = %#v", perms)
	}
}

// The legacy-floor catalog (drift's "what guardrail may have written") knows
// the V2 permission entry so a no-manifest file carrying it reports stale
// instead of invisible.
func TestLegacyFloorFragmentIncludesV2Permissions(t *testing.T) {
	frag, ok := legacyFloorFragment("opencode")
	if !ok {
		t.Fatal("opencode legacy floor fragment missing")
	}
	perms, ok := frag["permissions"].([]any)
	if !ok || len(perms) != 1 {
		t.Fatalf("legacy floor fragment permissions = %#v", frag["permissions"])
	}
	rule, ok := perms[0].(map[string]any)
	if !ok || rule["action"] != "external_directory" || rule["effect"] != "ask" {
		t.Fatalf("legacy V2 permission rule = %#v", rule)
	}
}
