package adapter

import (
	"reflect"
	"strings"
	"testing"

	"github.com/CtrlCarlitos/agent-guardrails/internal/policy"
)

// #469: Antigravity sometimes sends view_file with TargetFile. The strict
// per-tool argument list rejected the whole call ("argument TargetFile is not
// documented"), failing a legitimate read closed six times in three days.
// TargetFile is accepted as view_file's path when it is the only one, or
// when it names the same file as AbsolutePath; two different paths stay
// ambiguous and fail closed.
func TestAntigravityViewFileAcceptsTargetFile(t *testing.T) {
	for name, tc := range map[string]struct {
		args string
		want []string
	}{
		"TargetFile alone":         {`{"TargetFile":"/repo/main.go","StartLine":1,"EndLine":20}`, []string{"/repo/main.go"}},
		"both, same path":          {`{"AbsolutePath":"/repo/main.go","TargetFile":"/repo/main.go"}`, []string{"/repo/main.go"}},
		"AbsolutePath still works": {`{"AbsolutePath":"/repo/main.go"}`, []string{"/repo/main.go"}},
	} {
		got, err := ParseAntigravity("pre", strings.NewReader(`{"toolCall":{"name":"view_file","args":`+tc.args+`}}`))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got.Capability != policy.CapabilityReadDiscovery || !reflect.DeepEqual(got.Paths, tc.want) {
			t.Errorf("%s: capability %q paths %v, want read_discovery %v", name, got.Capability, got.Paths, tc.want)
		}
	}
	// The secret-path rule still sees a TargetFile read.
	got, err := ParseAntigravity("pre", strings.NewReader(`{"toolCall":{"name":"view_file","args":{"TargetFile":"/home/u/.ssh/id_ed25519"}}}`))
	if err != nil || !reflect.DeepEqual(got.Paths, []string{"/home/u/.ssh/id_ed25519"}) {
		t.Errorf("TargetFile secret read not projected: %v %v", got.Paths, err)
	}
}

func TestAntigravityViewFileAmbiguousOrUnknownArgumentsStillFailClosed(t *testing.T) {
	for name, args := range map[string]string{
		"two different paths": `{"AbsolutePath":"/repo/a.go","TargetFile":"/home/u/.ssh/id_ed25519"}`,
		"no path at all":      `{"StartLine":1}`,
		"an unknown argument": `{"AbsolutePath":"/repo/a.go","Sneaky":"x"}`,
	} {
		if _, err := ParseAntigravity("pre", strings.NewReader(`{"toolCall":{"name":"view_file","args":`+args+`}}`)); err == nil {
			t.Errorf("%s: parsed without error; want fail-closed", name)
		}
	}
}
