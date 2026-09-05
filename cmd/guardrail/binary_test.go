package main

import (
	"path/filepath"
	"testing"
)

func TestResolveBinaryPathNormalizesExplicitPaths(t *testing.T) {
	absoluteInput := filepath.Join(t.TempDir(), "bin") + string(filepath.Separator) + ".." + string(filepath.Separator) + "guardrail"
	wantAbsolute := filepath.Clean(absoluteInput)
	relativeInput := "." + string(filepath.Separator) + "bin" + string(filepath.Separator) + ".." + string(filepath.Separator) + "guardrail"
	wantRelative, err := filepath.Abs(relativeInput)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "absolute", input: absoluteInput, want: wantAbsolute},
		{name: "path-like relative", input: relativeInput, want: wantRelative},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveBinaryPath(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("resolveBinaryPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
