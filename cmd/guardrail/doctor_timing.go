package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/safetext"
)

func readTimingSamples(path string) []audit.TimingSample {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 1<<20))
	scanner.Buffer(make([]byte, 4096), 4097)
	var samples []audit.TimingSample
	for scanner.Scan() {
		var s audit.TimingSample
		if json.Unmarshal(scanner.Bytes(), &s) != nil || s.Host == "" || s.Kind == "" {
			continue
		}
		samples = append(samples, s)
		if len(samples) > audit.TimingKeep {
			samples = samples[1:]
		}
	}
	return samples
}

// printOptInTiming never pools versions, transports, runtimes or span kinds.
// A plugin knows the engine version only from an exact, unambiguous native
// session/call match. It never assumes the current installed binary answered.
func printOptInTiming(stdout io.Writer) {
	if !audit.TimingEnabled() {
		return
	}
	native := readTimingSamples(audit.TimingPath())
	versions := map[string]string{}
	for _, s := range native {
		if s.SessionID == "" || s.CallID == "" {
			continue
		}
		key := s.SessionID + "\x00" + s.CallID
		if old, ok := versions[key]; ok && old != s.Version {
			versions[key] = "ambiguous"
		} else {
			versions[key] = s.Version
		}
	}
	plugin := readTimingSamples(filepath.Join(filepath.Dir(audit.TimingPath()), "plugin-timing.jsonl"))
	for i := range plugin {
		v := versions[plugin[i].SessionID+"\x00"+plugin[i].CallID]
		if v != "ambiguous" {
			plugin[i].Version = v
		}
	}
	groups := map[string][]audit.TimingSample{}
	for _, s := range append(native, plugin...) {
		v := s.Version
		if v == "" {
			v = "unmeasured"
		}
		hv := "unmeasured"
		if s.HostVersion != nil {
			hv = *s.HostVersion
		}
		key := fmt.Sprintf("host=%s version=%s transport=%s kind=%s host_version=%s runtime=%s", s.Host, v, s.Transport, s.Kind, hv, s.Runtime)
		groups[key] = append(groups[key], s)
	}
	fmt.Fprintln(stdout, "opt-in timing (latest bounded samples; spans overlap, do not add them):")
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		fmt.Fprintln(stdout, "  no timing samples; GUARDRAIL_TIMING=1 must be set on the host/daemon that runs the hooks")
	}
	for _, key := range keys {
		samples := groups[key]
		values := map[string][]float64{}
		for _, s := range samples {
			for name, v := range s.Phases {
				if _, ok := values[name]; !ok {
					values[name] = nil
				}
				if v != nil {
					values[name] = append(values[name], *v)
				}
			}
		}
		names := make([]string, 0, len(values))
		for name := range values {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			xs := values[name]
			sort.Float64s(xs)
			if len(xs) == 0 {
				parts = append(parts, name+"=unmeasured")
				continue
			}
			parts = append(parts, fmt.Sprintf("%s=p50:%.3f/p95:%.3f ms (n=%d/%d)", name, percentile(xs, 50), percentile(xs, 95), len(xs), len(samples)))
		}
		fmt.Fprintf(stdout, "  %s n=%d %s\n", safetext.SingleLine(key), len(samples), safetext.SingleLine(strings.Join(parts, "; ")))
	}
}
