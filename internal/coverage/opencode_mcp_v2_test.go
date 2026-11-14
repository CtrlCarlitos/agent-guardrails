package coverage

import (
	"testing"
)

// OpenCode 2 groups servers under mcp.servers and inverts enabled to
// disabled (#534). doctor must inventory both shapes, and a server named by
// both (a half-migrated file) resolves to the V1 entry, matching V2's own
// normalization precedence.
func TestReadOpencodeMCPReadsV2ServersShape(t *testing.T) {
	v2 := []byte(`{"mcp":{"servers":{"serena":{"type":"local","command":["uvx","serena"]},"web":{"type":"remote","url":"https://example.test"},"off":{"type":"local","command":["x"],"disabled":true}}}}`)
	got, err := readOpencodeMCP(v2)
	if err != nil {
		t.Fatal(err)
	}
	want := []MCPServerConfig{
		{Name: "off", Command: "x", Args: []string{}, Disabled: true},
		{Name: "serena", Command: "uvx", Args: []string{"serena"}},
		{Name: "web", Remote: true},
	}
	assertServers(t, got, want)
}

func TestReadOpencodeMCPV2DefaultsToEnabled(t *testing.T) {
	// V2's field is the inverse: absent disabled means enabled.
	got, err := readOpencodeMCP([]byte(`{"mcp":{"servers":{"on":{"type":"local","command":["a"]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	assertServers(t, got, []MCPServerConfig{{Name: "on", Command: "a", Args: []string{}}})
}

func TestReadOpencodeMCPV1EntryWinsOnNameCollision(t *testing.T) {
	got, err := readOpencodeMCP([]byte(`{"mcp":{"v1":{"type":"local","command":["old"],"enabled":true},"servers":{"v1":{"type":"local","command":["new"]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	assertServers(t, got, []MCPServerConfig{{Name: "v1", Command: "old", Args: []string{}}})
}

func assertServers(t *testing.T, got, want []MCPServerConfig) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("servers = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Command != want[i].Command || got[i].Remote != want[i].Remote || got[i].Disabled != want[i].Disabled {
			t.Fatalf("servers[%d] = %#v, want %#v", i, got[i], want[i])
		}
		if len(got[i].Args) != len(want[i].Args) {
			t.Fatalf("servers[%d].Args = %#v, want %#v", i, got[i].Args, want[i].Args)
		}
	}
}
