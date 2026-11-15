package main

import (
	"io"
	"runtime"
	"time"

	"github.com/CtrlCarlitos/agent-guardrails/internal/audit"
	"github.com/CtrlCarlitos/agent-guardrails/internal/engine"
	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

type hookTiming struct {
	sample  audit.TimingSample
	tc      *engine.ToolCall
	started time.Time
}

func newHookTiming(kind, host, transport string, tc *engine.ToolCall, started time.Time) *hookTiming {
	if !audit.TimingEnabled() {
		return nil
	}
	return &hookTiming{tc: tc, started: started, sample: audit.TimingSample{
		Kind: kind, Host: host, Version: version, Runtime: runtime.GOOS + "/" + runtime.GOARCH + " " + runtime.Version(), Transport: transport,
		Phases: map[string]*float64{
			"adapter_parse_ms":         nil,
			"policy_setup_ms":          nil,
			"audit_write_ms":           nil,
			"response_encode_write_ms": nil,
			"timing_persist_ms":        nil,
			"host_dispatch_ms":         nil,
			"wrapper_dispatch_ms":      nil,
			"daemon_dial_ms":           nil,
			"daemon_roundtrip_ms":      nil,
			"engine_handling_ms":       nil,
			"response_write_ms":        nil,
		},
	}}
}

func (t *hookTiming) phase(name string, d time.Duration) {
	if t == nil {
		return
	}
	ms := float64(d.Nanoseconds()) / 1e6
	t.sample.Phases[name] = &ms
}
func (t *hookTiming) now() time.Time {
	if t == nil {
		return time.Time{}
	}
	return time.Now()
}
func (t *hookTiming) transport(value string) {
	if t != nil {
		t.sample.Transport = value
	}
}
func (t *hookTiming) evaluate(tc engine.ToolCall, p *policy.Policy) policy.Verdict {
	started := t.now()
	v := engine.Evaluate(tc, p)
	if t != nil {
		ms := float64(time.Since(started).Nanoseconds()) / 1e6
		if old := t.sample.Phases["engine_handling_ms"]; old != nil {
			ms += *old
		}
		t.sample.Phases["engine_handling_ms"] = &ms
	}
	return v
}
func (t *hookTiming) finish() {
	if t == nil {
		return
	}
	t.sample.SessionID = t.tc.SessionID
	t.sample.CallID = t.tc.CallID
	if t.sample.Kind == "hook" {
		t.phase("hook_total_ms", time.Since(t.started))
	} else {
		t.phase("sample_total_ms", time.Since(t.started))
	}
	_ = audit.WriteTiming(t.sample)
}

type timingWriter struct {
	io.Writer
	t *hookTiming
}

func (w timingWriter) Write(p []byte) (int, error) {
	started := time.Now()
	n, err := w.Writer.Write(p)
	ms := float64(time.Since(started).Nanoseconds()) / 1e6
	ms += *w.t.sample.Phases["response_write_ms"]
	w.t.sample.Phases["response_write_ms"] = &ms
	return n, err
}
func (t *hookTiming) writer(w io.Writer) io.Writer {
	if t == nil {
		return w
	}
	zero := float64(0)
	t.sample.Phases["response_write_ms"] = &zero
	return timingWriter{Writer: w, t: t}
}

func (t *hookTiming) since(name string, started time.Time) {
	if t != nil {
		t.phase(name, time.Since(started))
	}
}
func (t *hookTiming) emit(plane, phase string, tc engine.ToolCall, v policy.Verdict, stdout, stderr io.Writer) int {
	started := t.now()
	code := emitVerdict(plane, phase, tc, v, stdout, stderr)
	t.since("response_encode_write_ms", started)
	return code
}
