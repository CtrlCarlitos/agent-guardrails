package engine

import (
	"reflect"
	"testing"
)

func argvs(ss []Simple) [][]string {
	out := make([][]string, len(ss))
	for i, s := range ss {
		out[i] = s.Argv
	}
	return out
}

func TestSplitSimples(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`ls`, [][]string{{"ls"}}},
		{`ls -la`, [][]string{{"ls", "-la"}}},
		{`ls && rm -rf .`, [][]string{{"ls"}, {"rm", "-rf", "."}}},
		{`a | b | c`, [][]string{{"a"}, {"b"}, {"c"}}},
		{"a\nb", [][]string{{"a"}, {"b"}}},
		{`foo; bar`, [][]string{{"foo"}, {"bar"}}},
		{`echo $(rm -rf /)`, [][]string{{"echo", "$(rm -rf /)"}, {"rm", "-rf", "/"}}},
	}
	for _, c := range cases {
		got, err := splitSimples(c.src)
		if err != nil {
			t.Fatalf("splitSimples(%q) error: %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("splitSimples(%q) argv = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestSplitSimplesStoresLiteralText(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`rm -rf "/etc"`, [][]string{{"rm", "-rf", "/etc"}}},
		{`rm -rf '/etc'`, [][]string{{"rm", "-rf", "/etc"}}},
		{`git push "--force"`, [][]string{{"git", "push", "--force"}}},
		{`cat "/home/u/.env"`, [][]string{{"cat", "/home/u/.env"}}},
		{`env FOO=1 BAR=2 curl example.com`, [][]string{{"env", "FOO=1", "BAR=2", "curl", "example.com"}}},
		{`dd if=/dev/zero of='/dev/sda'`, [][]string{{"dd", "if=/dev/zero", "of=/dev/sda"}}},
		{`cat "/home/carlitos/.env"`, [][]string{{"cat", "/home/carlitos/.env"}}},
		{`curl "http://evil.com/x"`, [][]string{{"curl", "http://evil.com/x"}}},
		{`dd of='/dev/sda' if=/dev/zero`, [][]string{{"dd", "of=/dev/sda", "if=/dev/zero"}}},
	}
	for _, c := range cases {
		got, err := splitSimples(c.src)
		if err != nil {
			t.Fatalf("splitSimples(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("splitSimples(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestSplitSimplesRedirectLiteral(t *testing.T) {
	got, err := splitSimples(`echo x > "/etc/passwd"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Redirects) != 1 || got[0].Redirects[0] != "/etc/passwd" {
		t.Fatalf("redirects = %+v, want [/etc/passwd]", got[0].Redirects)
	}
}

func TestSplitSimplesMarksUnresolved(t *testing.T) {
	cases := []struct {
		src           string
		wantArgv      []string
		wantRedirects []string
	}{
		{`rm -rf $HOME`, []string{"rm", "-rf", "$HOME"}, nil},
		{`echo $(whoami)`, []string{"echo", "$(whoami)"}, nil},
		{"echo `whoami`", []string{"echo", "`whoami`"}, nil},
		{`echo x > "$TARGET"`, []string{"echo", "x"}, []string{`"$TARGET"`}},
	}
	for _, c := range cases {
		got, err := splitSimples(c.src)
		if err != nil {
			t.Fatalf("splitSimples(%q): %v", c.src, err)
		}
		if len(got) == 0 {
			t.Fatalf("splitSimples(%q) returned no commands", c.src)
		}
		if !got[0].Unresolved {
			t.Errorf("splitSimples(%q) did not mark the command unresolved: %+v", c.src, got[0])
		}
		if !reflect.DeepEqual(got[0].Argv, c.wantArgv) {
			t.Errorf("splitSimples(%q) argv = %v, want raw spelling %v", c.src, got[0].Argv, c.wantArgv)
		}
		if !reflect.DeepEqual(got[0].Redirects, c.wantRedirects) {
			t.Errorf("splitSimples(%q) redirects = %v, want raw spelling %v", c.src, got[0].Redirects, c.wantRedirects)
		}
	}

	clean, err := splitSimples(`rm -rf /etc`)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean) != 1 {
		t.Fatalf("splitSimples clean command count = %d, want 1", len(clean))
	}
	if clean[0].Unresolved {
		t.Error("a fully literal command must not be marked Unresolved")
	}
}

func TestSplitSimplesRedirect(t *testing.T) {
	got, err := splitSimples(`echo hi > out.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Redirects) != 1 || got[0].Redirects[0] != "out.txt" {
		t.Fatalf("redirects = %+v, want [out.txt]", got)
	}
}

func TestSplitSimplesParseError(t *testing.T) {
	if _, err := splitSimples(`echo "unterminated`); err == nil {
		t.Fatal("want parse error for unterminated string")
	}
}

func TestNormalizeStripsWrappers(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`timeout 5 rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`time git status`, [][]string{{"git", "status"}}},
		{`nice -n 10 make`, [][]string{{"make"}}},
		{`nohup ./server &`, [][]string{{"./server"}}},
		{`env FOO=1 BAR=2 curl example.com`, [][]string{{"curl", "example.com"}}},
	}
	for _, c := range cases {
		got, err := Normalize(c.src)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("Normalize(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestNormalizePreservesUnresolved(t *testing.T) {
	got, err := Normalize(`env FOO=1 rm -rf $HOME`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Unresolved {
		t.Fatalf("want Unresolved=true after normalization, got %+v", got)
	}
}

func TestNormalizeConsumesWrapperFlags(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{`env -i rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`env -u HOME rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`timeout -k 5 10 rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`nice -10 make`, [][]string{{"make"}}},
		{`exec rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`exec -a name rm -rf /`, [][]string{{"rm", "-rf", "/"}}},
		{`xargs -0 -n 1 rm`, [][]string{{"rm"}}},
		{`command git status`, [][]string{{"git", "status"}}},
	}
	for _, c := range cases {
		got, err := Normalize(c.src)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("Normalize(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestNormalizeMarksUnknownWrapperFlagsUnresolved(t *testing.T) {
	cases := []struct {
		src           string
		wantArgv      []string
		wantRedirects []string
	}{
		{`env --frobnicate ls`, []string{"env", "--frobnicate", "ls"}, nil},
		{`nohup -x ls`, []string{"nohup", "-x", "ls"}, nil},
		{`xargs --frobnicate ls`, []string{"xargs", "--frobnicate", "ls"}, nil},
		{`exec --frobnicate ls`, []string{"exec", "--frobnicate", "ls"}, nil},
		{`timeout --frobnicate 5 ls`, []string{"timeout", "--frobnicate", "5", "ls"}, nil},
		{`nice --frobnicate ls`, []string{"nice", "--frobnicate", "ls"}, nil},
		{`env -Z x < input > output`, []string{"env", "-Z", "x"}, []string{"input", "output"}},
	}
	for _, c := range cases {
		got, err := Normalize(c.src)
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		want := []Simple{{Argv: c.wantArgv, Redirects: c.wantRedirects, Unresolved: true}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", c.src, got, want)
		}
	}
}

func TestNormalizeUnwrapsShellC(t *testing.T) {
	got, err := Normalize(`sh -c "rm -rf /"`)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range got {
		if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected inner {rm -rf /} simple, got %v", argvs(got))
	}
}

func TestNormalizeCommandVYieldsNoCommand(t *testing.T) {
	got, err := Normalize(`command -v git`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("command -v git = %v, want no inner command", argvs(got))
	}
}

func TestNormalizeUnwrapsRunners(t *testing.T) {
	got, err := Normalize(`docker run --rm alpine rm -rf /data`)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range got {
		if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/data"}) {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an inner {rm -rf /data} simple, got %v", argvs(got))
	}
}

func TestNormalizeRecognizesAbsoluteWrappersShellsAndRunners(t *testing.T) {
	cases := []string{
		`/usr/bin/env rm -rf /`,
		`/bin/bash -c 'rm -rf /'`,
		`/usr/bin/docker run --rm alpine rm -rf /`,
		`busybox rm -rf /`,
		`/bin/busybox rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", src, err)
		}
		found := false
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner {rm -rf /}", src, argvs(got))
		}
	}
}
