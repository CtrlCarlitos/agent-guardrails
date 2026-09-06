package genconfig

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

type opencodePermissionRule struct {
	permission string
	pattern    string
	value      any
}

func readOpencodePermissionRules(t *testing.T, path, category string) []opencodePermissionRule {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return parseOpencodePermissionRules(t, raw, category)
}

func parseOpencodePermissionRules(t *testing.T, raw []byte, category string) []opencodePermissionRule {
	t.Helper()
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	var permission map[string]json.RawMessage
	if err := json.Unmarshal(root["permission"], &permission); err != nil {
		t.Fatal(err)
	}
	return parseOpencodeRuleObject(t, permission[category])
}

func parseOpencodeFlattenedPermissions(t *testing.T, raw []byte) []opencodePermissionRule {
	t.Helper()
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(root["permission"]))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("permission is not an object: %v", err)
	}
	var rules []opencodePermissionRule
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			t.Fatal(err)
		}
		var scalar string
		if err := json.Unmarshal(value, &scalar); err == nil {
			rules = append(rules, opencodePermissionRule{permission: key.(string), pattern: "*", value: scalar})
			continue
		}
		categoryRules := parseOpencodeRuleObject(t, value)
		for _, rule := range categoryRules {
			rule.permission = key.(string)
			rules = append(rules, rule)
		}
	}
	return rules
}

func parseOpencodeRuleObject(t *testing.T, raw []byte) []opencodePermissionRule {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		t.Fatalf("permission category is not an object: %v", err)
	}
	var rules []opencodePermissionRule
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := dec.Decode(&value); err != nil {
			t.Fatal(err)
		}
		rules = append(rules, opencodePermissionRule{pattern: key.(string), value: value})
	}
	return rules
}

func opencodeGlobMatches(pattern, value string) bool {
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	value = strings.ReplaceAll(value, "\\", "/")
	var expression strings.Builder
	for i := 0; i < len(pattern); {
		switch {
		case pattern[i] == '*':
			expression.WriteString(".*")
			i++
		case pattern[i] == '?':
			expression.WriteByte('.')
			i++
		default:
			expression.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
			i++
		}
	}
	body := expression.String()
	if strings.HasSuffix(body, " .*") {
		body = strings.TrimSuffix(body, " .*") + "( .*)?"
	}
	return regexp.MustCompile("(?s)^" + body + "$").MatchString(value)
}

func assertOpencodeRulesOrdered(t *testing.T, rules []opencodePermissionRule) {
	t.Helper()
	previousRank := -1
	previousPattern := ""
	for _, rule := range rules {
		rank := map[any]int{"allow": 1, "ask": 2, "deny": 3}[rule.value]
		if rank < previousRank || rank == previousRank && rule.pattern < previousPattern {
			t.Fatalf("permission rules are not ordered by verdict then pattern: %q follows %q", rule.pattern, previousPattern)
		}
		previousRank = rank
		previousPattern = rule.pattern
	}
}

func TestOpencodeGlobMatchesDocumentedWildcards(t *testing.T) {
	for _, tt := range []struct {
		pattern string
		value   string
		want    bool
	}{
		{pattern: "*", value: "nested/path", want: true},
		{pattern: "src/?.go", value: "src/x.go", want: true},
		{pattern: "src/?.go", value: "src/xy.go", want: false},
		{pattern: "src/?", value: "src//", want: true},
	} {
		if got := opencodeGlobMatches(tt.pattern, tt.value); got != tt.want {
			t.Errorf("match(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
		}
	}
}

// OpenCode resolves overlapping permission patterns with findLast.
func opencodeFindLast(rules []opencodePermissionRule, value string) string {
	var verdict string
	for _, rule := range rules {
		if opencodeGlobMatches(rule.pattern, value) {
			if candidate, ok := rule.value.(string); ok {
				verdict = candidate
			}
		}
	}
	return verdict
}

func opencodeFindLastPermission(rules []opencodePermissionRule, permission, pattern string) string {
	var verdict string
	for _, rule := range rules {
		if opencodeGlobMatches(rule.permission, permission) && opencodeGlobMatches(rule.pattern, pattern) {
			if candidate, ok := rule.value.(string); ok {
				verdict = candidate
			}
		}
	}
	return verdict
}

func TestOpencodePluginSourceRetainsDeploymentPlaceholder(t *testing.T) {
	if !bytes.Contains(OpencodePluginJS, []byte(`"__GUARDRAIL_BIN__"`)) {
		t.Fatal("embedded OpenCode plugin source is missing the deployment placeholder")
	}
}

func TestOpencodePluginForEscapesAndUsesExactBinaryPath(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "guardrail\"\\\n\u2603\t")
	encoded, err := json.Marshal(binary)
	if err != nil {
		t.Fatal(err)
	}
	plugin := OpencodePluginFor(binary)
	wantDeclaration := []byte("const GUARDRAIL_BIN = " + string(encoded) + ";")
	if !bytes.Contains(plugin, wantDeclaration) {
		t.Fatalf("generated declaration does not contain the JSON-encoded path %q", wantDeclaration)
	}

	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute the generated OpenCode plugin")
	}
	fakeGuardrail := `#!/bin/sh
IFS= read -r _ || :
printf '%s' '{"decision":"allow","reason":"accepted"}'
`
	if err := os.WriteFile(binary, []byte(fakeGuardrail), 0o755); err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(dir, "guardrail.mjs")
	if err := os.WriteFile(pluginPath, plugin, 0o644); err != nil {
		t.Fatal(err)
	}
	runner := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const instance = await loaded.default({ directory: process.cwd() });
await instance["tool.execute.before"](
	{ tool: "bash", sessionID: "test-session" },
	{ args: { command: "true" } },
);
process.stdout.write("allowed");
`
	cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated plugin did not use the exact adversarial path: %v\n%s", err, output)
	}
	if string(output) != "allowed" {
		t.Fatalf("stdout = %q, want allowed", output)
	}
}

func TestOpencodePluginRequiresExplicitAllow(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to exercise the embedded OpenCode plugin")
	}

	dir := t.TempDir()
	binary := filepath.Join(dir, "guardrail")
	fakeGuardrail := `#!/bin/sh
IFS= read -r _ || :
case "$GUARDRAIL_TEST_RESPONSE" in
	allow) printf '%s' '{"decision":"allow","reason":"accepted"}' ;;
	ask) printf '%s' '{"decision":"ask","reason":"confirm it"}' ;;
	deny) printf '%s' '{"decision":"deny","reason":"blocked it"}' ;;
	unknown) printf '%s' '{"decision":"unexpected","reason":"bad verdict"}' ;;
	empty) ;;
	malformed) printf '%s' 'not-json' ;;
esac
`
	if err := os.WriteFile(binary, []byte(fakeGuardrail), 0o755); err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(dir, "guardrail.mjs")
	if err := os.WriteFile(pluginPath, OpencodePluginFor(binary), 0o644); err != nil {
		t.Fatal(err)
	}

	runner := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.default({ directory: process.cwd() });
try {
	await plugin["tool.execute.before"](
		{ tool: "bash", sessionID: "test-session" },
		{ args: { command: "true" } },
	);
	process.stdout.write("allowed");
} catch (error) {
	process.stderr.write(error instanceof Error ? error.message : String(error));
	process.exit(42);
}
`
	tests := []struct {
		response string
		wantErr  string
	}{
		{response: "allow"},
		{response: "ask", wantErr: "needs confirmation - confirm it"},
		{response: "deny", wantErr: "guardrail: blocked it"},
		{response: "unknown", wantErr: "guardrail: bad verdict"},
		{response: "empty", wantErr: "guardrail: no decision returned"},
		{response: "malformed", wantErr: "guardrail: unparseable response"},
	}
	for _, tt := range tests {
		t.Run(tt.response, func(t *testing.T) {
			cmd := exec.Command(node, "--input-type=module", "--eval", runner, pluginPath)
			cmd.Env = append(os.Environ(), "GUARDRAIL_TEST_RESPONSE="+tt.response)
			output, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("explicit allow was blocked: %v\n%s", err, output)
				}
				if string(output) != "allowed" {
					t.Fatalf("stdout = %q, want allowed", output)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s response was allowed", tt.response)
			}
			if !strings.Contains(string(output), tt.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", output, tt.wantErr)
			}
		})
	}
}

func TestOpencodeConfigBashPermissions(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	bash := frag["permission"].(map[string]any)["bash"].(orderedPermissionRules)
	if bash["*"] != "allow" {
		t.Errorf(`bash["*"] = %q, want "allow"`, bash["*"])
	}
	if bash["rm -rf *"] != "deny" {
		t.Errorf(`bash["rm -rf *"] = %q, want "deny"`, bash["rm -rf *"])
	}
	if bash["chmod -R *"] != "ask" {
		t.Errorf(`bash["chmod -R *"] = %q, want "ask"`, bash["chmod -R *"])
	}
}

func TestOpencodeConfigReadEditPermissions(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	read := frag["permission"].(map[string]any)["read"].(orderedPermissionRules)
	edit := frag["permission"].(map[string]any)["edit"].(orderedPermissionRules)
	if read["**/.ssh/**"] != "deny" {
		t.Errorf(`read["**/.ssh/**"] = %q`, read["**/.ssh/**"])
	}
	if read["**/.env.example"] != "allow" {
		t.Errorf(`read["**/.env.example"] = %q, want allow`, read["**/.env.example"])
	}
	if edit[".claude/**"] != "deny" {
		t.Errorf(`edit[".claude/**"] = %q, want deny`, edit[".claude/**"])
	}
	if edit[".github/workflows/**"] != "ask" {
		t.Errorf(`edit[".github/workflows/**"] = %q, want ask`, edit[".github/workflows/**"])
	}
}

func TestOpencodeSecretDirsOutrankSecretAllow(t *testing.T) {
	for _, tt := range []struct {
		name  string
		allow string
		path  string
	}{
		{name: "exact", allow: "**/.ssh/**", path: "/home/u/.ssh/id_rsa"},
		{name: "overlapping", allow: "**/.ssh/*.example", path: "/home/u/.ssh/key.example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pol := secretPol()
			pol.Slots.SecretAllow = []string{tt.allow}
			raw, err := json.Marshal(OpencodeConfig(pol, "/x/guardrail.js"))
			if err != nil {
				t.Fatal(err)
			}
			for _, category := range []string{"read", "edit"} {
				rules := parseOpencodePermissionRules(t, raw, category)
				if got := opencodeFindLast(rules, tt.path); got != "deny" {
					t.Errorf("%s findLast permission for %q = %q, want deny", category, tt.path, got)
				}
			}
		})
	}
}

func TestOpencodeConfigProtectsGuardrailOwnMachinery(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	edit := frag["permission"].(map[string]any)["edit"].(orderedPermissionRules)
	want := []string{
		"guardrail.toml",
		"**/guardrail.toml",
		".guardrail/**",
		"opencode.json",
		"**/opencode.json",
		".agents/hooks.json",
		"**/.gemini/config/hooks.json",
		"**/.local/bin/guardrail",
		"**/bin/guardrail",
	}
	for _, path := range want {
		if edit[path] != "deny" {
			t.Errorf("OpenCode edit permission for %q = %q, want deny", path, edit[path])
		}
	}
}

func TestOpencodeConfigProtectsOperatorConfig(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	edit := frag["permission"].(map[string]any)["edit"].(orderedPermissionRules)
	for _, path := range []string{
		"**/.config/guardrail/**",
		"**/guardrail/waivers.toml",
	} {
		if edit[path] != "deny" {
			t.Errorf("OpenCode edit permission for %q = %q, want deny", path, edit[path])
		}
		if got := edit["//"+path]; got != nil {
			t.Errorf("OpenCode edit permission contains Claude-only absolute form %q = %v", "//"+path, got)
		}
	}
}

func TestOpencodeConfigPluginRegistered(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	plugins := frag["plugin"].([]string)
	if len(plugins) != 1 || plugins[0] != "/x/guardrail.js" {
		t.Errorf("plugin = %v", plugins)
	}
}

func TestOpencodeConfigOrderedStandaloneOutput(t *testing.T) {
	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	first, err := json.MarshalIndent(frag, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.MarshalIndent(frag, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("standalone OpenCode output is not byte-idempotent:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
	if !json.Valid(first) {
		t.Fatalf("standalone OpenCode output is invalid JSON:\n%s", first)
	}
	if !bytes.Contains(first, []byte("\n    \"bash\": {\n")) {
		t.Fatalf("standalone OpenCode output is not pretty JSON:\n%s", first)
	}
	for _, category := range []string{"bash", "read", "edit"} {
		assertOpencodeRulesOrdered(t, parseOpencodePermissionRules(t, first, category))
	}
}

func TestOrderedPermissionRulesPreserveJSONEscaping(t *testing.T) {
	key := "quoted\"\\\n<key>"
	want := map[string]any{"nested": "quoted\"\\\n<value>"}
	raw, err := json.MarshalIndent(orderedPermissionRules{key: want}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("ordered rules emitted invalid escaped JSON: %v\n%s", err, raw)
	}
	if !reflect.DeepEqual(got[key], want) {
		t.Fatalf("escaped value = %#v, want %#v", got[key], want)
	}
}

func TestMergeOpencodePreservesExistingProjectConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "opencode.json")
	os.WriteFile(p, []byte(`{
		"plugin": ["superpowers@git+https://github.com/obra/superpowers.git"],
		"permission": {
			"bash": {"*": "allow", "git commit *": "ask"},
			"external_directory": {"~/projects/**": "allow"}
		}
	}`), 0o644)

	frag := OpencodeConfig(secretPol(), "/x/guardrail.js")
	if err := MergeInto(p, frag); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(p)
	var m map[string]any
	json.Unmarshal(raw, &m)
	perm := m["permission"].(map[string]any)

	bash := perm["bash"].(map[string]any)
	if bash["git commit *"] != "ask" {
		t.Errorf("existing project rule lost: %v", bash["git commit *"])
	}
	if bash["rm -rf *"] != "deny" {
		t.Errorf("guardrail rule not added: %v", bash["rm -rf *"])
	}
	if _, ok := perm["external_directory"]; !ok {
		t.Error("external_directory block lost")
	}

	plugins := m["plugin"].([]any)
	if len(plugins) != 2 {
		t.Fatalf("want superpowers + guardrail = 2 plugin entries, got %v", plugins)
	}
}

func TestMergeIntoOpencodePermissionPrecedence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "opencode.json")
	existing := `{
		"permission": {
			"edit": {
				"/**": "allow",
				"/home/**": "allow",
				"~/**": "allow",
				"**/*.example": "ask",
				"**/workflows/**": "deny"
			}
		}
	}`
	if err := os.WriteFile(p, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := MergeInto(p, OpencodeConfig(secretPol(), "/x/guardrail.js")); err != nil {
		t.Fatal(err)
	}

	rules := readOpencodePermissionRules(t, p, "edit")
	assertOpencodeRulesOrdered(t, rules)
	for _, tt := range []struct {
		path string
		want string
	}{
		{path: "/home/carlitos/.config/guardrail/operator.toml", want: "deny"},
		{path: "~/.ssh/id_rsa", want: "deny"},
		{path: "nested/.env.example", want: "ask"},
		{path: ".github/workflows/release.yml", want: "deny"},
	} {
		if got := opencodeFindLast(rules, tt.path); got != tt.want {
			t.Errorf("findLast permission for %q = %q, want %q", tt.path, got, tt.want)
		}
	}
}
