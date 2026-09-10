package night

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, time.September, 10, 21, 0, 0, 0, time.UTC)

func TestDefaultPathUsesOperatorConfigDirectory(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("Unix environment-variable behavior")
	}

	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	got, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "guardrail", "night.toml"); got != want {
		t.Fatalf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestWriteAndLoadActiveMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guardrail", "night.toml")
	want := Marker{Until: testNow.Add(8 * time.Hour), SetBy: "workstation:1234"}
	if err := Write(path, want); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Active || !got.Until.Equal(want.Until) || got.SetBy != want.SetBy {
		t.Fatalf("Load() = %+v, want active marker %+v", got, want)
	}
	if got.Banner() != "NIGHT MODE until 2026-09-11T05:00:00Z" {
		t.Fatalf("Banner() = %q", got.Banner())
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("marker permissions = %o, want 600", got)
	}
}

func TestLoadMissingAndExpiredMarkersAreInactive(t *testing.T) {
	missing, err := Load(filepath.Join(t.TempDir(), "missing.toml"), testNow)
	if err != nil || missing.Active {
		t.Fatalf("missing marker = %+v, %v; want inactive without error", missing, err)
	}

	path := filepath.Join(t.TempDir(), "night.toml")
	if err := Write(path, Marker{Until: testNow, SetBy: "workstation:1234"}); err != nil {
		t.Fatal(err)
	}
	expired, err := Load(path, testNow)
	if err != nil || expired.Active {
		t.Fatalf("expired marker = %+v, %v; want inactive without error", expired, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expired marker must remain for operator inspection: %v", err)
	}
}

func TestLoadRejectsInvalidMarker(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "malformed TOML", body: "until = [", want: "parsing"},
		{name: "missing until", body: `set_by = "host:1"`, want: "until"},
		{name: "missing set_by", body: `until = 2026-09-11T05:00:00Z`, want: "set_by"},
		{name: "unknown key", body: "until = 2026-09-11T05:00:00Z\nset_by = \"host:1\"\nextra = true", want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "night.toml")
			if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
				t.Fatal(err)
			}
			state, err := Load(path, testNow)
			if err == nil || state.Active || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() = %+v, %v; want inactive %q error", state, err, tt.want)
			}
		})
	}
}

func TestLoadRejectsNonRegularMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "night.toml")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := Load(path, testNow)
	if err == nil || state.Active || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load() = %+v, %v; want inactive regular-file error", state, err)
	}
}

func TestRemoveIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "night.toml")
	if err := Write(path, Marker{Until: testNow.Add(time.Hour), SetBy: "host:1"}); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := Remove(path); err != nil {
		t.Fatalf("second Remove() = %v, want nil", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("marker still exists after Remove(): %v", err)
	}
}
