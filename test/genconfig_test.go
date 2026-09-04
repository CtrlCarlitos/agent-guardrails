package test

import (
	"bytes"
	"flag"
	"os"
	"os/exec"
	"testing"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

func TestGenConfigClaudeGolden(t *testing.T) {
	bin := buildBinary(t) // from contract_test.go, same package
	cmd := exec.Command(bin, "gen-config", "claude", "--print", "--binary", "/usr/local/bin/guardrail")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	golden := "fixtures/claude/settings-floor.golden.json"
	if *updateGolden {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update once): %v", err)
	}
	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("gen-config output drift.\n--- got ---\n%s\n--- want ---\n%s", out.String(), want)
	}
}

func TestGenConfigAntigravityGolden(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "gen-config", "antigravity", "--print", "--binary", "/usr/local/bin/guardrail")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	golden := "fixtures/antigravity/hooks-floor.golden.json"
	if *updateGolden {
		os.WriteFile(golden, out.Bytes(), 0o644)
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update once): %v", err)
	}
	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("gen-config antigravity output drift.\n--- got ---\n%s\n--- want ---\n%s", out.String(), want)
	}
}

func TestGenConfigOpencodeGolden(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "gen-config", "opencode", "--print", "--binary", "/usr/local/bin/guardrail", "--plugin-dir", "/usr/local/lib/guardrail")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	golden := "fixtures/opencode/settings-floor.golden.json"
	if *updateGolden {
		os.WriteFile(golden, out.Bytes(), 0o644)
		t.Logf("wrote %s", golden)
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update once): %v", err)
	}
	if !bytes.Equal(want, out.Bytes()) {
		t.Fatalf("gen-config opencode output drift.\n--- got ---\n%s\n--- want ---\n%s", out.String(), want)
	}
}
