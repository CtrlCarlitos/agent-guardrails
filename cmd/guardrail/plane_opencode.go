package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/CtrlCarlitos/agent-guardrails/internal/genconfig"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// OpenCode plane wiring, selected by the detected major (#534, ADR-0034).
//
// V1: a single-file artifact (<state>/guardrail.js) registered under the
// `plugin` key. V2: a directory artifact (<state>/guardrail/index.js)
// registered under `plugins` — V2 skips configured single-file plugin paths —
// plus the native `permissions` array carrying the external_directory ask.
// A major of 0 (binary not found, version unparsable) emits the V1 shape
// unchanged and is reported loudly; the fleet's 1.19.x must keep working
// byte-for-byte.
type opencodeWiring struct {
	major      int    // 1 or 2; never 0 here
	configKey  string // "plugin" (V1) or "plugins" (V2)
	entryPath  string // value written under configKey
	artifact   string // file whose content is the plugin source
	permission bool   // V2 also emits the permissions array
}

func opencodeWiringFor(stateDir string) opencodeWiring {
	if opencodeMajor() == 2 {
		dir := filepath.Join(stateDir, "guardrail")
		return opencodeWiring{major: 2, configKey: "plugins", entryPath: dir, artifact: filepath.Join(dir, "index.js"), permission: true}
	}
	file := filepath.Join(stateDir, "guardrail.js")
	return opencodeWiring{major: 1, configKey: "plugin", entryPath: file, artifact: file}
}

// opencodeFragment is the config fragment for the detected major.
func opencodeFragment(w opencodeWiring, base *policy.Policy) genconfig.Fragment {
	if w.permission {
		return genconfig.OpencodeConfigV2(w.entryPath)
	}
	return genconfig.OpencodeConfig(base, w.entryPath)
}

// opencodeEntryInstalled reports whether the config holds a guardrail entry
// under this wiring's key. Like the pre-V2 check it matches by basename, so
// a repo-level entry written by `guardrail sync` also counts: registration
// asks "is some guardrail wiring present", not "is the global artifact the
// one this binary would write" — that stricter question is handler drift's.
func opencodeEntryInstalled(doc map[string]any, w opencodeWiring) bool {
	basename := filepath.Base(w.entryPath)
	entries, _ := doc[w.configKey].([]any)
	for _, entry := range entries {
		s, ok := entry.(string)
		if !ok {
			continue
		}
		if filepath.Base(s) == basename {
			return true
		}
	}
	return false
}

// opencodeOtherMajorEntryNames describes guardrail entries found under the
// other major's key, for loud cross-major reporting.
func opencodeOtherMajorEntryInstalled(doc map[string]any, w opencodeWiring) bool {
	otherKey := "plugin"
	otherBase := "guardrail.js"
	if w.configKey == "plugin" {
		otherKey = "plugins"
		otherBase = "guardrail"
	}
	entries, _ := doc[otherKey].([]any)
	for _, entry := range entries {
		s, ok := entry.(string)
		if !ok {
			continue
		}
		if filepath.Base(s) == otherBase {
			return true
		}
	}
	return false
}

// opencodeRegisteredMajorAware drives reconciliation: on a detected major
// only that major's entry counts, so a machine that flipped majors
// re-enables and converges. With the major unknown, either shape counts — a
// missing binary must not force a re-enable loop.
func opencodeRegisteredMajorAware(doc map[string]any) bool {
	stateDir, err := planePluginDir()
	if err != nil {
		return false
	}
	w := opencodeWiringFor(stateDir)
	if w.major == opencodeMajor() {
		return opencodeEntryInstalled(doc, w)
	}
	v1 := opencodeWiring{major: 1, configKey: "plugin", entryPath: filepath.Join(stateDir, "guardrail.js")}
	v2 := opencodeWiring{major: 2, configKey: "plugins", entryPath: filepath.Join(stateDir, "guardrail")}
	return opencodeEntryInstalled(doc, v1) || opencodeEntryInstalled(doc, v2)
}

// opencodeStatusState renders the opencode line for `plane status` and
// `doctor`, naming the detected major and entry shape. A cross-major wiring
// is loud: it reads as NOT registered with the remedy, and counts as a
// doctor problem through the "present, " prefix.
func opencodeStatusState(doc map[string]any) string {
	major := opencodeMajor()
	stateDir, err := planePluginDir()
	if err != nil {
		return fmt.Sprintf("unknown (%v)", err)
	}
	w := opencodeWiringFor(stateDir)
	detected := map[int]string{1: "opencode 1", 2: "opencode 2"}[major]
	if detected == "" {
		detected = "opencode major unknown"
	}
	if w.major == major && opencodeEntryInstalled(doc, w) {
		return fmt.Sprintf("guardrail integration registered (%s, %s entry)", detected, w.configKey)
	}
	if opencodeRegisteredMajorAware(doc) {
		return fmt.Sprintf("guardrail integration registered (%s, %s entry)", detected, w.configKey)
	}
	other := ""
	if opencodeOtherMajorEntryInstalled(doc, w) {
		otherMajor := "V1"
		if w.major == 1 {
			otherMajor = "V2"
		}
		other = fmt.Sprintf(" (a %s plugin entry is installed; OpenCode %d skips it)", otherMajor, w.major)
	}
	return fmt.Sprintf("present, integration NOT registered for %s%s; run 'guardrail plane enable opencode'", detected, other)
}

// noteOpencodeMajorUnknown warns, when wiring opencode without a detectable
// binary, that the V1 shape is assumed (#534): the V2 curl installer
// replaces the V1 binary in place, and V2 silently skips configured
// single-file plugin paths, so a wrong guess means no enforcement.
func noteOpencodeMajorUnknown(planes []string, stderr io.Writer) {
	if !slices.Contains(planes, "opencode") || opencodeMajor() != 0 {
		return
	}
	fmt.Fprintln(stderr, "guardrail: opencode major not detected (no opencode binary on PATH or unparsable --version); wiring the OpenCode 1 shape. If this machine runs OpenCode 2, run 'guardrail plane enable opencode' with the binary on PATH — OpenCode 2 skips single-file plugin entries.")
}

// opencodeMajorChoice resolves the emission major for gen-config and sync:
// an explicit --major (already validated as 1 or 2) wins; otherwise the
// installed binary is probed; an undetectable major degrades to the V1
// shape. Deliberately silent — these are scripted commands whose output
// callers parse, and an undetectable major is the ordinary case on machines
// without an opencode binary; the loud signal for the assumption lives in
// plane enable/setup (noteOpencodeMajorUnknown) and doctor's status line.
func opencodeMajorChoice(requested int, stderr io.Writer) int {
	if requested == 1 || requested == 2 {
		return requested
	}
	if major := opencodeMajor(); major != 0 {
		return major
	}
	return 1
}

// readOpencodePlaneDoc loads the opencode.json document for the status and
// drift paths; nil when unreadable.
func readOpencodePlaneDoc() map[string]any {
	path, err := planeConfigPath("opencode")
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	return doc
}
