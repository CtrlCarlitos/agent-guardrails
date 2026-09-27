package test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// defenderCall matches every Defender preference cmdlet that can widen what
// Microsoft Defender skips.
var defenderCall = regexp.MustCompile(`(?i)\b(Add|Set)-MpPreference\b[^\r\n]*`)

// exactFileExclusion is the only Defender call the installer may make: exclude
// the one binary path, held in $script:Exe.
// Set-MpPreference is refused too: it replaces the operator's whole exclusion
// list rather than adding to it.
var exactFileExclusion = regexp.MustCompile(`(?i)^Add-MpPreference\s+-ExclusionPath\s+(\$script:Exe|` + "`" + `"\$\(\$script:Exe\)` + "`" + `")\W*$`)

// scriptExe is the assignment that gives $script:Exe its value.
var scriptExe = regexp.MustCompile(`(?m)^\s*\$script:Exe\s*=\s*(.+)$`)

// defenderProblems lists every Defender call in a PowerShell script that is
// not the exact-file exclusion, plus any $script:Exe value that does not name
// guardrail.exe itself.
func defenderProblems(script string) []string {
	var problems []string
	for _, m := range defenderCall.FindAllString(script, -1) {
		call := strings.TrimSpace(m)
		if !exactFileExclusion.MatchString(call) {
			problems = append(problems, "Defender call is not the exact-file exclusion: "+call)
		}
	}
	for _, m := range scriptExe.FindAllStringSubmatch(script, -1) {
		value := strings.TrimSpace(m[1])
		if value == "''" || value == `""` {
			continue // the empty initialiser
		}
		if !strings.Contains(value, "'guardrail.exe'") {
			problems = append(problems, "$script:Exe does not name guardrail.exe: "+value)
		}
	}
	return problems
}

func TestDefenderGuardFlagsEveryWideningSpelling(t *testing.T) {
	for name, script := range map[string]string{
		"directory":      "Add-MpPreference -ExclusionPath $script:Dest",
		"literal dir":    `Add-MpPreference -ExclusionPath "C:\Users\u\.local\bin"`,
		"process":        "Add-MpPreference -ExclusionProcess 'guardrail.exe'",
		"extension":      "Add-MpPreference -ExclusionExtension '.exe'",
		"set replaces":   "Set-MpPreference -ExclusionPath $script:Exe",
		"exe is the dir": "$script:Exe = $script:Dest\nAdd-MpPreference -ExclusionPath $script:Exe",
	} {
		if p := defenderProblems(script); len(p) == 0 {
			t.Errorf("%s: guard accepted a widening exclusion: %q", name, script)
		}
	}
}

// The installer adds a Defender exclusion so a hook spawn is not scanned
// every time (#132). An excluded path that a session can overwrite is a hole,
// so #146 paired the exclusion with the P5 rule on the binary and required the
// exclusion to name exactly the binary: never its directory, a process name or
// an extension. Nothing else asserted that scope; an elevated harness run is
// the only place the call executes, and CI is not elevated.
func TestInstallerDefenderExclusionIsExactlyTheBinary(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "install.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	if !defenderCall.MatchString(script) {
		t.Fatal("install.ps1 makes no Defender call; update this guard if the exclusion moved")
	}
	for _, p := range defenderProblems(script) {
		t.Error(p)
	}
}
