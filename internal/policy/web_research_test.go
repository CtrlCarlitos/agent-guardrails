package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsWebResearchOnlyOperatorConfigCanRelax(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "guardrail.toml")
	if err := os.WriteFile(path, []byte("[web_research]\nenforcement = \"off\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ov, err := LoadOverlay(path)
	if err != nil {
		t.Fatal(err)
	}
	base, err := LoadBase()
	if err != nil {
		t.Fatal(err)
	}
	// Even a programmatically supplied Base cannot smuggle in the opt-out.
	base.WebResearchOff = true
	for _, mode := range []string{"", "on", "off", "invalid"} {
		merged, _, err := Merge(base, ov, "dev", &OperatorConfig{WebResearchEnforcement: mode}, root)
		if err != nil {
			t.Fatal(err)
		}
		if merged.WebResearchOff != (mode == "off") {
			t.Fatalf("mode=%s off=%v", mode, merged.WebResearchOff)
		}
	}
}

func TestWindowsWebResearchInvalidOperatorConfigRemovesOptOut(t *testing.T) {
	for _, raw := range []string{
		"[web_research]\nenforcement = true\n",
		"[web_research]\nenforcement = \"invalid\"\n",
		"[web_research]\nenforcement = \"off\"\n[web_hosts]\nglobal = [\"*.example.com\"]\n",
		"[web_research]\nenforcement = \"off\"\n[relative]\nsecret_allow = true\n",
	} {
		writeOperatorConfig(t, raw)
		op, err := LoadOperatorConfig()
		if err == nil || op.WebResearchEnforcement == "off" {
			t.Fatalf("raw=%q op=%+v err=%v", raw, op, err)
		}
	}
}
