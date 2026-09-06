package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestNormalizeRedirectOnlyStatements(t *testing.T) {
	cases := map[string][]string{
		`> /etc/passwd`:        {"/etc/passwd"},
		`>/etc/passwd`:         {"/etc/passwd"},
		`>> /etc/passwd`:       {"/etc/passwd"},
		`2> /etc/error.log`:    {"/etc/error.log"},
		`&> /etc/combined.log`: {"/etc/combined.log"},
		`exec 3> /etc/passwd`:  {"/etc/passwd"},
		`exec 3>> /etc/passwd`: {"/etc/passwd"},
	}
	for src, wantRedirects := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := []Simple{{Redirects: wantRedirects}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", src, got, want)
		}
	}
}

func TestNormalizeCommandLookupRetainsRedirects(t *testing.T) {
	for _, c := range []struct {
		src       string
		wantReads []string
	}{
		{`command -v git > /repo/CLAUDE.md`, nil},
		{`command -V git > /repo/CLAUDE.md`, nil},
		{`command > /repo/CLAUDE.md`, nil},
		{`command -v git < /repo/.env > /repo/CLAUDE.md`, []string{"/repo/.env"}},
	} {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		want := []Simple{{Redirects: []string{"/repo/CLAUDE.md"}, ReadRedirects: c.wantReads}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", c.src, got, want)
		}
	}
}

func TestNormalizeClassifiesWriteRedirectsDirectionally(t *testing.T) {
	cases := []struct {
		src        string
		wantCount  int
		wantWrites []string
		wantReads  []string
	}{
		{`> out`, 1, []string{"out"}, nil},
		{`>> append`, 1, []string{"append"}, nil},
		{`>| clobber`, 1, []string{"clobber"}, nil},
		{`&> all`, 1, []string{"all"}, nil},
		{`&>> append-all`, 1, []string{"append-all"}, nil},
		{`<> read-write`, 1, []string{"read-write"}, []string{"read-write"}},
		{`< input`, 1, nil, []string{"input"}},
		{`3< input`, 1, nil, []string{"input"}},
		{`2>&1`, 0, nil, nil},
		{`2>&-`, 0, nil, nil},
		{`>&2`, 0, nil, nil},
		{`>&-`, 0, nil, nil},
		{`0<&1`, 0, nil, nil},
		{`<&-`, 0, nil, nil},
		{`>& output`, 1, []string{"output"}, nil},
		{"cat <<'/etc/passwd'\nbody\n/etc/passwd", 1, nil, nil},
		{"cat <<-'/etc/passwd'\nbody\n/etc/passwd", 1, nil, nil},
		{`cat <<< /etc/passwd`, 1, nil, nil},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		if len(got) != c.wantCount {
			t.Errorf("Normalize(%q) count = %d, want %d: %+v", c.src, len(got), c.wantCount, got)
			continue
		}
		if len(got) == 1 && !reflect.DeepEqual(got[0].Redirects, c.wantWrites) {
			t.Errorf("Normalize(%q) writes = %v, want %v", c.src, got[0].Redirects, c.wantWrites)
		}
		if len(got) == 1 && !reflect.DeepEqual(got[0].ReadRedirects, c.wantReads) {
			t.Errorf("Normalize(%q) reads = %v, want %v", c.src, got[0].ReadRedirects, c.wantReads)
		}
	}
}

func TestNormalizePreservesRedirectOrderWithinEachDirection(t *testing.T) {
	got, err := Normalize(`cat > first < input >> second <> both`, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("Normalize returned %+v, want one Simple", got)
	}
	wantWrites := []string{"first", "second", "both"}
	if !reflect.DeepEqual(got[0].Redirects, wantWrites) {
		t.Errorf("writes = %v, want %v", got[0].Redirects, wantWrites)
	}
	wantReads := []string{"input", "both"}
	if !reflect.DeepEqual(got[0].ReadRedirects, wantReads) {
		t.Errorf("reads = %v, want %v", got[0].ReadRedirects, wantReads)
	}
}

func TestNormalizePreservesRedirectDirectionsThroughWrapper(t *testing.T) {
	got, err := Normalize(`env cat < input > output`, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{{
		Argv:          []string{"cat"},
		Redirects:     []string{"output"},
		ReadRedirects: []string{"input"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize = %+v, want %+v", got, want)
	}
}

func TestNormalizeCompoundStatementRedirects(t *testing.T) {
	cases := []struct {
		src  string
		want []Simple
	}{
		{
			`{ :; } > /repo/CLAUDE.md`,
			[]Simple{{Redirects: []string{"/repo/CLAUDE.md"}}, {Argv: []string{":"}}},
		},
		{
			`( :) < /repo/input`,
			[]Simple{{ReadRedirects: []string{"/repo/input"}}, {Argv: []string{":"}}},
		},
		{
			`if true; then :; fi <> /repo/state`,
			[]Simple{
				{Redirects: []string{"/repo/state"}, ReadRedirects: []string{"/repo/state"}},
				{Argv: []string{"true"}},
				{Argv: []string{":"}},
			},
		},
		{
			`{ :; } > "$TARGET"`,
			[]Simple{{Redirects: []string{`"$TARGET"`}, Unresolved: true}, {Argv: []string{":"}}},
		},
		{
			`{ : > /repo/inner; } > /repo/outer`,
			[]Simple{
				{Redirects: []string{"/repo/outer"}},
				{Argv: []string{":"}, Redirects: []string{"/repo/inner"}},
			},
		},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", c.src, got, c.want)
		}
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
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("Normalize(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestNormalizePreservesUnresolved(t *testing.T) {
	got, err := Normalize(`env FOO=1 rm -rf $HOME`, "")
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
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Fatalf("Normalize(%q): %v", c.src, err)
		}
		if !reflect.DeepEqual(argvs(got), c.want) {
			t.Errorf("Normalize(%q) = %v, want %v", c.src, argvs(got), c.want)
		}
	}
}

func TestNormalizeConsumesAddedWrapperOptions(t *testing.T) {
	cases := []string{
		`setsid -f --fork -w --wait -c --ctty rm -rf /`,
		`setsid -fw rm -rf /`,
		`stdbuf -iL -o 0 -eL rm -rf /`,
		`stdbuf -o0 rm -rf /`,
		`stdbuf --input=L --output 0 --error=L rm -rf /`,
		`ionice -c2 -n 7 -t rm -rf /`,
		`ionice -tc2 rm -rf /`,
		`ionice --class 2 --classdata=7 --ignore rm -rf /`,
		`watch -n2 -d -t -b -e rm -rf /`,
		`watch -dtn2 rm -rf /`,
		`watch --interval 2 --differences --no-title rm -rf /`,
		`watch --differences=permanent rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := [][]string{{"rm", "-rf", "/"}}
		if !reflect.DeepEqual(argvs(got), want) {
			t.Errorf("Normalize(%q) = %v, want %v", src, argvs(got), want)
		}
	}
}

func TestNormalizeAddedWrappersHonorOptionTerminator(t *testing.T) {
	cases := []string{
		`setsid -- rm -rf /`,
		`stdbuf -- rm -rf /`,
		`ionice -- rm -rf /`,
		`watch -- rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := [][]string{{"rm", "-rf", "/"}}
		if !reflect.DeepEqual(argvs(got), want) {
			t.Errorf("Normalize(%q) = %v, want %v", src, argvs(got), want)
		}
	}

	got, err := Normalize(`chroot -- /new-root rm -rf /`, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{{Argv: []string{"rm", "-rf", "/"}, Unresolved: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize chroot -- = %+v, want %+v", got, want)
	}
}

func TestNormalizeAddedWrapperErrorsFailClosed(t *testing.T) {
	cases := []string{
		`setsid --future-option rm -rf /`,
		`stdbuf --future-option rm -rf /`,
		`ionice --future-option rm -rf /`,
		`watch --future-option rm -rf /`,
		`chroot --future-option /new-root rm -rf /`,
		`stdbuf --output`,
		`ionice --class`,
		`ionice -tc`,
		`watch --interval`,
		`watch -dtn`,
		`watch`,
		`chroot --userspec`,
		`chroot`,
		`chroot /new-root`,
		`setsid -fz rm -rf /`,
		`ionice -tz rm -rf /`,
		`watch -dtz rm -rf /`,
		`watch --no-title=value rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 1 || !got[0].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want one unresolved Simple", src, got)
		}
	}
}

func TestNormalizeAddedWrappersPreserveRedirectDirections(t *testing.T) {
	for _, prefix := range []string{
		`setsid`,
		`stdbuf -o0`,
		`ionice -c2`,
	} {
		src := prefix + ` cat < input > output`
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := []Simple{{
			Argv:          []string{"cat"},
			Redirects:     []string{"output"},
			ReadRedirects: []string{"input"},
		}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", src, got, want)
		}
	}
}

func TestNormalizeWatchTreatsCommandAsShellSource(t *testing.T) {
	cases := []struct {
		src  string
		want []Simple
	}{
		{
			`watch 'rm -rf /'`,
			[]Simple{{Argv: []string{"rm", "-rf", "/"}}},
		},
		{
			`watch 'printf ok; rm -rf /'`,
			[]Simple{{Argv: []string{"printf", "ok"}}, {Argv: []string{"rm", "-rf", "/"}}},
		},
		{
			`watch 'printf ok > /etc/passwd'`,
			[]Simple{{Argv: []string{"printf", "ok"}, Redirects: []string{"/etc/passwd"}}},
		},
		{
			`watch 'printf ok; cat < inner-input' < outer-input > outer-output`,
			[]Simple{
				{Redirects: []string{"outer-output"}, ReadRedirects: []string{"outer-input"}},
				{Argv: []string{"printf", "ok"}},
				{Argv: []string{"cat"}, ReadRedirects: []string{"inner-input"}},
			},
		},
		{
			`watch 'printf ok' > "$TARGET"`,
			[]Simple{
				{Redirects: []string{`"$TARGET"`}, Unresolved: true},
				{Argv: []string{"printf", "ok"}, Unresolved: true},
			},
		},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", c.src, got, c.want)
		}
	}
}

func TestNormalizeChrootDerivationsAreUnresolved(t *testing.T) {
	for _, src := range []string{
		`chroot --userspec=root --groups wheel /new-root rm -rf /repo`,
		`chroot --userspec root --groups=wheel /new-root rm -rf /repo`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := []Simple{{Argv: []string{"rm", "-rf", "/repo"}, Unresolved: true}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", src, got, want)
		}
	}

	got, err := Normalize(`chroot /new-root cat < input > output`, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{{
		Argv:          []string{"cat"},
		Redirects:     []string{"output"},
		ReadRedirects: []string{"input"},
		Unresolved:    true,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize chroot redirects = %+v, want %+v", got, want)
	}

	got, err = Normalize(`chroot /new-root command -v git < input > output`, "")
	if err != nil {
		t.Fatal(err)
	}
	want = []Simple{{
		Redirects:     []string{"output"},
		ReadRedirects: []string{"input"},
		Unresolved:    true,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize empty chroot argv = %+v, want %+v", got, want)
	}
}

func TestNormalizeMarksUnknownWrapperFlagsUnresolved(t *testing.T) {
	cases := []struct {
		src               string
		wantArgv          []string
		wantRedirects     []string
		wantReadRedirects []string
	}{
		{`env --frobnicate ls`, []string{"env", "--frobnicate", "ls"}, nil, nil},
		{`nohup -x ls`, []string{"nohup", "-x", "ls"}, nil, nil},
		{`xargs --frobnicate ls`, []string{"xargs", "--frobnicate", "ls"}, nil, nil},
		{`exec --frobnicate ls`, []string{"exec", "--frobnicate", "ls"}, nil, nil},
		{`timeout --frobnicate 5 ls`, []string{"timeout", "--frobnicate", "5", "ls"}, nil, nil},
		{`nice --frobnicate ls`, []string{"nice", "--frobnicate", "ls"}, nil, nil},
		{`env -Z x < input > output`, []string{"env", "-Z", "x"}, []string{"output"}, []string{"input"}},
	}
	for _, c := range cases {
		got, err := Normalize(c.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", c.src, err)
			continue
		}
		want := []Simple{{Argv: c.wantArgv, Redirects: c.wantRedirects, ReadRedirects: c.wantReadRedirects, Unresolved: true}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", c.src, got, want)
		}
	}
}

func TestNormalizeUnwrapsShellC(t *testing.T) {
	got, err := Normalize(`sh -c "rm -rf /"`, "")
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

func TestNormalizeUnwrapsAddedShellC(t *testing.T) {
	for _, shell := range []string{"fish", "csh", "tcsh", "mksh", "ash"} {
		src := shell + ` -c "rm -rf /"`
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
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

func TestNormalizeUnwrapsClusteredShellC(t *testing.T) {
	for _, src := range []string{
		`mksh -lc "rm -rf /"`,
		`ash -lc "rm -rf /"`,
		`csh -fc "rm -rf /"`,
		`tcsh -fc "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
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

func TestNormalizeShellCDoesNotScanPositionalOrLongOptions(t *testing.T) {
	for _, src := range []string{
		`mksh script -lc "rm -rf /"`,
		`tcsh script -fc "rm -rf /"`,
		`bash --rcfile -c "rm -rf /"`,
		`fish --init-command -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				t.Errorf("Normalize(%q) incorrectly exposed inner {rm -rf /}: %v", src, argvs(got))
			}
		}
	}
}

func TestNormalizeShellCParsesPreCommandOptionsByArity(t *testing.T) {
	for _, src := range []string{
		`bash --noprofile -c "rm -rf /"`,
		`bash -o posix -c "rm -rf /"`,
		`bash -oposix -c "rm -rf /"`,
		`bash -O extglob -c "rm -rf /"`,
		`bash -lOextglob -c "rm -rf /"`,
		`bash --rcfile=/tmp/bashrc -c "rm -rf /"`,
		`bash --init-file /tmp/bashrc -c "rm -rf /"`,
		`sh -o posix -c "rm -rf /"`,
		`mksh -oposix -c "rm -rf /"`,
		`fish --no-config -c "rm -rf /"`,
		`fish --init-command 'printf init' -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
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

func TestNormalizeUnknownShellOptionFailsClosed(t *testing.T) {
	for _, src := range []string{
		`bash --future-option -c "rm -rf /"`,
		`bash -Z -c "rm -rf /"`,
		`fish --future-option -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 1 || !got[0].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want one unresolved Simple", src, got)
		}
	}
}

func TestNormalizeEmptyShellScriptOperandStopsOptionParsing(t *testing.T) {
	got, err := Normalize(`bash '' -c "rm -rf /"`, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
			t.Fatalf("empty script operand exposed false inner command: %v", argvs(got))
		}
	}
}

func TestNormalizeMixedShellClustersAfterC(t *testing.T) {
	for _, src := range []string{
		`bash -co posix "rm -rf /"`,
		`bash -coposix "rm -rf /"`,
		`bash -cO extglob "rm -rf /"`,
		`bash -cOextglob "rm -rf /"`,
		`bash -cl "rm -rf /"`,
		`bash -cxl "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
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

func TestNormalizeMalformedMixedShellClustersFailClosed(t *testing.T) {
	for _, src := range []string{
		`bash -co`,
		`bash -co posix`,
		`bash -cO`,
		`bash -cO extglob`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 1 || !got[0].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want one unresolved Simple", src, got)
		}
	}
}

func TestNormalizeUsesShellSpecificOptionGrammar(t *testing.T) {
	for _, src := range []string{
		`dash -I -c "rm -rf /"`,
		`bash --debug -c "rm -rf /"`,
		`bash --debugger -c "rm -rf /"`,
		`bash --login -c "rm -rf /"`,
		`bash --noediting -c "rm -rf /"`,
		`bash --norc -c "rm -rf /"`,
		`bash --posix -c "rm -rf /"`,
		`bash --pretty-print -c "rm -rf /"`,
		`bash --restricted -c "rm -rf /"`,
		`bash --verbose -c "rm -rf /"`,
		`bash --noprofile -l -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
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

	for _, src := range []string{
		`dash -h -c "rm -rf /"`,
		`bash -l --noprofile -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 1 || !got[0].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want one unresolved Simple", src, got)
		}
	}

	for _, src := range []string{
		`zsh -b -c "rm -rf /"`,
		`bash -- -c "rm -rf /"`,
		`bash --help -c "rm -rf /"`,
		`bash --version -c "rm -rf /"`,
		`bash --dump-strings -c "rm -rf /"`,
		`bash --dump-po-strings -c "rm -rf /"`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		for _, s := range got {
			if reflect.DeepEqual(s.Argv, []string{"rm", "-rf", "/"}) {
				t.Errorf("Normalize(%q) incorrectly exposed inner command: %v", src, argvs(got))
			}
		}
	}
}

func TestNormalizeChrootRetainsZeroResultAsUnresolved(t *testing.T) {
	for _, src := range []string{
		`chroot /new-root command -v git`,
		`chroot /new-root command -V git`,
		`chroot /new-root command`,
		`chroot /new-root exec`,
	} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := []Simple{{Unresolved: true}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", src, got, want)
		}
	}
}

func TestNormalizeNonChrootZeroResultRemainsEmpty(t *testing.T) {
	for _, src := range []string{`command -v git`, `command -V git`, `command`, `exec`} {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 0 {
			t.Errorf("Normalize(%q) = %+v, want no Simples", src, got)
		}
	}

	got, err := Normalize(`chroot /new-root command git status`, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{{Argv: []string{"git", "status"}, Unresolved: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize chroot positional command = %+v, want %+v", got, want)
	}
}

func TestNormalizeCommandVYieldsNoCommand(t *testing.T) {
	got, err := Normalize(`command -v git`, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("command -v git = %v, want no inner command", argvs(got))
	}
}

func TestNormalizeUnwrapsRunners(t *testing.T) {
	got, err := Normalize(`docker run --rm alpine rm -rf /data`, "")
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

func TestNormalizeDockerFamilyRunExecValuedOptions(t *testing.T) {
	cases := []string{
		`docker run --rm -v /:/host alpine rm -rf /`,
		`docker run -e A=b alpine rm -rf /`,
		`docker run --volume=/:/host -eA=b -p8080:80 -w/host -u0 alpine rm -rf /`,
		`docker --context dev run --mount type=bind,src=/,dst=/host --name x alpine rm -rf /`,
		`docker exec --env A=b --workdir /host container rm -rf /`,
		`podman run --network host alpine rm -rf /`,
		`nerdctl exec --env=A=b container rm -rf /`,
		`docker run -- --name rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
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

func TestRunnerInnerKeepsFlagsAfterImage(t *testing.T) {
	got, err := runnerInner([]string{"docker", "run", "alpine", "--name", "x", "rm", "-rf", "/"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--name", "x", "rm", "-rf", "/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runnerInner() = %q, want %q", got, want)
	}
}

func TestRunnerInnerRejectsMissingDockerOptionValues(t *testing.T) {
	for _, argv := range [][]string{
		{"docker", "run", "--name"},
		{"docker", "run", "--hostname"},
		{"docker", "run", "--platform"},
		{"docker", "run", "--label"},
		{"docker", "run", "--pull"},
		{"podman", "exec", "--workdir"},
		{"nerdctl", "run", "-v"},
	} {
		if _, err := runnerInner(argv); err == nil {
			t.Errorf("runnerInner(%q) error = nil, want missing-value error", argv)
		}
	}
}

func TestNormalizeDockerRunUsesRunSpecificOptionArity(t *testing.T) {
	cases := []string{
		`docker run --rm --hostname sandbox -v /:/host alpine rm -rf /host`,
		`docker run --platform linux/amd64 alpine rm -rf /`,
		`docker run --platform=linux/amd64 alpine rm -rf /`,
		`docker run --label role=test alpine rm -rf /`,
		`docker run --label=role=test alpine rm -rf /`,
		`docker run --pull always alpine rm -rf /`,
		`docker run --pull=always alpine rm -rf /`,
		`docker run --hostname --force --label /tmp/label alpine rm -rf /`,
		`docker run -itv/:/host -lrole=test alpine rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		found := false
		for _, s := range got {
			if len(s.Argv) >= 2 && s.Argv[0] == "rm" && s.Argv[1] == "-rf" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Normalize(%q) = %v, want inner rm -rf", src, argvs(got))
		}
	}
}

func TestNormalizeDockerRunDetachKeysExactly(t *testing.T) {
	cases := []struct {
		src  string
		want [][]string
	}{
		{
			`docker run --detach-keys ctrl-x alpine rm -rf /`,
			[][]string{
				{"docker", "run", "--detach-keys", "ctrl-x", "alpine", "rm", "-rf", "/"},
				{"rm", "-rf", "/"},
			},
		},
		{
			`docker run --detach-keys=ctrl-x alpine rm -rf /`,
			[][]string{
				{"docker", "run", "--detach-keys=ctrl-x", "alpine", "rm", "-rf", "/"},
				{"rm", "-rf", "/"},
			},
		},
	}
	for _, tc := range cases {
		got, err := Normalize(tc.src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", tc.src, err)
			continue
		}
		if gotArgv := argvs(got); !reflect.DeepEqual(gotArgv, tc.want) {
			t.Errorf("Normalize(%q) = %q, want %q", tc.src, gotArgv, tc.want)
		}
	}
}

func TestDockerRunDetachKeysMissingValueFailsClosed(t *testing.T) {
	argv := []string{"docker", "run", "--detach-keys"}
	_, err := runnerInner(argv)
	if err == nil || !strings.Contains(err.Error(), "requires a value") {
		t.Fatalf("runnerInner(%q) error = %v, want requires-value error", argv, err)
	}
	v := evalBash(t, `docker run --detach-keys`)
	if v == nil || v.RuleID != "P3.unresolved" {
		t.Fatalf("missing --detach-keys -> %+v, want non-allow/P3.unresolved", v)
	}
}

func TestNormalizeDockerExecUsesExecSpecificOptionArity(t *testing.T) {
	cases := []string{
		`docker exec --detach-keys ctrl-x -e A=b -u 0 -w /tmp container rm -rf /`,
		`docker exec --detach-keys=ctrl-x -iteA=b -u0 -w/tmp container rm -rf /`,
		`podman exec --env-file /tmp/env container rm -rf /`,
		`nerdctl exec --privileged container rm -rf /`,
	}
	for _, src := range cases {
		got, err := Normalize(src, "")
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
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

func TestDockerRunExecUnknownOrMalformedOptionsFailClosed(t *testing.T) {
	commands := []string{
		`docker run --future value alpine rm -rf /`,
		`docker exec --future value container rm -rf /`,
		`docker run --rm=maybe alpine rm -rf /`,
		`docker exec --privileged=maybe container rm -rf /`,
		`docker exec --hostname sandbox container rm -rf /`,
	}
	for _, command := range commands {
		v := evalBash(t, command)
		if v == nil || v.RuleID != "P3.unresolved" {
			t.Errorf("%q -> %+v, want non-allow/P3.unresolved", command, v)
		}
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
		got, err := Normalize(src, "")
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

func TestNormalizeTracksLiteralCdCwd(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "src", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Normalize(`cd src; cd nested; rm -rf build`, repo)
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{
		{Argv: []string{"cd", "src"}, Cwd: repo},
		{Argv: []string{"cd", "nested"}, Cwd: filepath.Join(repo, "src")},
		{Argv: []string{"rm", "-rf", "build"}, Cwd: filepath.Join(repo, "src", "nested")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize cd chain = %+v, want %+v", got, want)
	}

	got, err = Normalize(`cd -- /etc; rm -rf .`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	want = []Simple{
		{Argv: []string{"cd", "--", "/etc"}, Cwd: "/repo"},
		{Argv: []string{"rm", "-rf", "."}, Cwd: "/etc"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize cd -- = %+v, want %+v", got, want)
	}
}

func TestNormalizeTracksChainedConditionalCdSuccessPath(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "src", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Normalize(`cd src && cd nested && rm -rf build`, repo)
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	wantCwd := filepath.Join(repo, "src", "nested")
	if !reflect.DeepEqual(last.Argv, []string{"rm", "-rf", "build"}) || last.Cwd != wantCwd || last.Unresolved {
		t.Fatalf("last = %+v, want resolved rm in %s", last, wantCwd)
	}
}

func TestNormalizeUnknownCdInvalidatesFollowingCwd(t *testing.T) {
	commands := []string{
		`cd; rm -rf .`,
		`cd -; rm -rf .`,
		`cd $TARGET; rm -rf .`,
		`cd one two; rm -rf .`,
		`cd -Z /etc; rm -rf .`,
		`pushd /etc; rm -rf .`,
		`popd; rm -rf .`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != "" || !last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want unknown cwd and unresolved", command, last)
		}
	}
}

func TestNormalizeCdScopeBoundaries(t *testing.T) {
	cases := []struct {
		command string
		wantCwd string
	}{
		{`(cd /etc); rm -rf build`, "/repo"},
		{`cd /etc | cat; rm -rf build`, "/repo"},
		{`value=$(cd /etc); rm -rf build`, "/repo"},
		{`cat <(cd /etc); rm -rf build`, "/repo"},
		{`bash -c 'cd /etc'; rm -rf build`, "/repo"},
	}
	for _, tc := range cases {
		got, err := Normalize(tc.command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", tc.command, err)
			continue
		}
		last := got[len(got)-1]
		if !reflect.DeepEqual(last.Argv, []string{"rm", "-rf", "build"}) || last.Cwd != tc.wantCwd {
			t.Errorf("Normalize(%q) last = %+v, want rm cwd %q", tc.command, last, tc.wantCwd)
		}
	}

	got, err := Normalize(`{ cd /etc; rm -rf .; }`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.Cwd != "/etc" {
		t.Fatalf("brace-group rm = %+v, want cwd /etc", last)
	}
}

func TestNormalizeIsolatedScopesTrackTheirOwnCd(t *testing.T) {
	commands := []string{
		`(cd /etc; rm -rf .)`,
		`printf x | { cd /etc; rm -rf .; }`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if !reflect.DeepEqual(last.Argv, []string{"rm", "-rf", "."}) || last.Cwd != "/etc" {
			t.Errorf("Normalize(%q) last = %+v, want rm cwd /etc", command, last)
		}
	}
}

func TestNormalizeUncertainControlFlowInvalidatesJoin(t *testing.T) {
	commands := []string{
		`if condition; then cd /etc; fi; rm -rf .`,
		`while condition; do cd /etc; done; rm -rf .`,
		`for item in $ITEMS; do cd /etc; done; rm -rf .`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != "" || !last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want unknown cwd and unresolved", command, last)
		}
	}
}

func TestNormalizeInnerShellAndWatchUseStatementCwd(t *testing.T) {
	commands := []string{
		`cd /etc; bash -c 'rm -rf .'`,
		`cd /etc; watch 'rm -rf .'`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if !reflect.DeepEqual(last.Argv, []string{"rm", "-rf", "."}) || last.Cwd != "/etc" {
			t.Errorf("Normalize(%q) last = %+v, want rm cwd /etc", command, last)
		}
	}
}

func TestNormalizeRelativeCdWithEmptyCwdIsUnknown(t *testing.T) {
	got, err := Normalize(`cd relative; rm -rf .`, "")
	if err != nil {
		t.Fatal(err)
	}
	last := got[len(got)-1]
	if last.Cwd != "" || !last.Unresolved {
		t.Fatalf("last = %+v, want unknown cwd and unresolved", last)
	}
}

func TestNormalizeCdSuccessAndFailureOutcomes(t *testing.T) {
	repo := t.TempDir()
	missing := filepath.Join(repo, "missing")
	notDir := filepath.Join(repo, "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{missing, notDir} {
		command := fmt.Sprintf(`cd /etc; cd %q; rm -rf .`, target)
		got, err := Normalize(command, repo)
		if err != nil {
			t.Fatal(err)
		}
		last := got[len(got)-1]
		if last.Cwd != "/etc" || last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want known cwd /etc", command, last)
		}
	}

	got, err := Normalize(fmt.Sprintf(`cd %q && rm -rf /`, missing), repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, simple := range got {
		if reflect.DeepEqual(simple.Argv, []string{"rm", "-rf", "/"}) {
			t.Fatalf("known failed cd exposed unreachable rm: %+v", got)
		}
	}

	created := filepath.Join(repo, "created")
	got, err = Normalize(fmt.Sprintf(`mkdir %q; cd %q; pwd`, created, created), repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
		t.Fatalf("post-mutation cd last = %+v, want unresolved cwd", last)
	}
}

func TestNormalizeCdPathAssignmentsAndModes(t *testing.T) {
	repo := t.TempDir()
	localSSL := filepath.Join(repo, "ssl")
	if err := os.Mkdir(localSSL, 0o700); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	physicalTarget := filepath.Join(out, "target")
	if err := os.Mkdir(physicalTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(repo, "link")
	if err := os.Symlink(physicalTarget, link); err != nil {
		t.Skipf("create symlink: %v", err)
	}

	cases := []struct {
		command string
		wantCwd string
	}{
		{`CDPATH=/etc cd ssl; pwd`, "/etc/ssl"},
		{`CDPATH=/etc; cd ssl; pwd`, "/etc/ssl"},
		{`OTHER=value cd ./ssl; pwd`, localSSL},
		{`cd -L link; pwd`, link},
		{`cd -P link; pwd`, physicalTarget},
		{`cd -L link/..; pwd`, repo},
		{`cd -P link/..; pwd`, out},
	}
	for _, test := range cases {
		got, err := Normalize(test.command, repo)
		if err != nil {
			t.Errorf("Normalize(%q): %v", test.command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != test.wantCwd || last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want cwd %q", test.command, last, test.wantCwd)
		}
	}

	t.Setenv("CDPATH", "/etc")
	got, err := Normalize(`cd ssl; pwd`, repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "/etc/ssl" || last.Unresolved {
		t.Fatalf("ambient CDPATH last = %+v, want /etc/ssl", last)
	}
	got, err = Normalize(`cd ./ssl; pwd`, repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != localSSL || last.Unresolved {
		t.Fatalf("dot-relative CDPATH bypass last = %+v, want %s", last, localSSL)
	}

	t.Setenv("CDPATH", "")
	commandCDPath := t.TempDir()
	for _, directory := range []string{"first", "next"} {
		if err := os.Mkdir(filepath.Join(commandCDPath, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got, err = Normalize(fmt.Sprintf(`CDPATH=%q cd first; cd next; pwd`, commandCDPath), repo)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(commandCDPath, "first"); got[len(got)-1].Cwd != want || got[len(got)-1].Unresolved {
		t.Fatalf("temporary CDPATH assignment last = %+v, want failed second cd to retain %s", got[len(got)-1], want)
	}

	got, err = Normalize(`cd -LP /etc; pwd`, repo)
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
		t.Fatalf("conflicting cd modes last = %+v, want unresolved cwd", last)
	}
}

func TestNormalizeUnknownCwdIsStickyAcrossRecursiveSources(t *testing.T) {
	commands := []string{
		`cd "$TARGET"; cd /etc; pwd`,
		`cd "$TARGET"; bash -c 'cd /etc; pwd'`,
		`cd "$TARGET"; watch 'cd /etc; pwd'`,
		`cd "$TARGET"; eval 'cd /etc; pwd'`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != "" || !last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want sticky unknown cwd", command, last)
		}
	}
}

func TestNormalizeEvalUsesCurrentShellState(t *testing.T) {
	got, err := Normalize(`eval 'cd /etc'; pwd`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "/etc" || last.Unresolved {
		t.Fatalf("eval cd last = %+v, want cwd /etc", last)
	}
	foundRm := false
	got, err = Normalize(`eval 'rm -rf /'`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	for _, simple := range got {
		foundRm = foundRm || reflect.DeepEqual(simple.Argv, []string{"rm", "-rf", "/"})
	}
	if !foundRm {
		t.Fatalf("eval did not expose inner rm: %+v", got)
	}

	got, err = Normalize(`eval "$SOURCE"; pwd`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "" || !last.Unresolved {
		t.Fatalf("dynamic eval last = %+v, want unresolved cwd", last)
	}
}

func TestNormalizeReusesStaticControlReachability(t *testing.T) {
	commands := []string{
		`false && rm -rf /`,
		`true || rm -rf /`,
		`if false; then rm -rf /; fi`,
		`case x in y) rm -rf /;; x) printf ok;; esac`,
		`while false; do rm -rf /; done`,
		`until true; do rm -rf /; done`,
		`for item in; do rm -rf /; done`,
	}
	for _, command := range commands {
		got, err := Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		for _, simple := range got {
			if reflect.DeepEqual(simple.Argv, []string{"rm", "-rf", "/"}) {
				t.Errorf("Normalize(%q) exposed unreachable rm: %+v", command, got)
			}
		}
	}
}

func TestNormalizeFunctionsOnlyWhenInvoked(t *testing.T) {
	got, err := Normalize(`danger() { rm -rf /; }`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("uncalled function emitted Simples: %+v", got)
	}

	got, err = Normalize(`danger() { rm -rf /; }; danger`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	foundRm := false
	for _, simple := range got {
		foundRm = foundRm || reflect.DeepEqual(simple.Argv, []string{"rm", "-rf", "/"})
	}
	if !foundRm {
		t.Fatalf("invoked function did not emit body: %+v", got)
	}

	got, err = Normalize(`move() { cd /etc; }; move; pwd`, "/repo")
	if err != nil {
		t.Fatal(err)
	}
	if last := got[len(got)-1]; last.Cwd != "/etc" || last.Unresolved {
		t.Fatalf("function cwd last = %+v, want /etc", last)
	}

	for _, command := range []string{
		`recur() { recur; }; recur; pwd`,
		`move() { cd /etc; }; "$FN"; pwd`,
	} {
		got, err = Normalize(command, "/repo")
		if err != nil {
			t.Errorf("Normalize(%q): %v", command, err)
			continue
		}
		last := got[len(got)-1]
		if last.Cwd != "" || !last.Unresolved {
			t.Errorf("Normalize(%q) last = %+v, want unresolved cwd", command, last)
		}
	}
}
