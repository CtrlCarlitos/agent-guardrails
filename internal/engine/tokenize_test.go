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
		got, err := Normalize(src)
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
		got, err := Normalize(c.src)
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
		got, err := Normalize(c.src)
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
	got, err := Normalize(`cat > first < input >> second <> both`)
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
	got, err := Normalize(`env cat < input > output`)
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
		got, err := Normalize(c.src)
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
		got, err := Normalize(src)
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
		got, err := Normalize(src)
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := [][]string{{"rm", "-rf", "/"}}
		if !reflect.DeepEqual(argvs(got), want) {
			t.Errorf("Normalize(%q) = %v, want %v", src, argvs(got), want)
		}
	}

	got, err := Normalize(`chroot -- /new-root rm -rf /`)
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
		got, err := Normalize(src)
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
		got, err := Normalize(src)
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
		got, err := Normalize(c.src)
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
		got, err := Normalize(src)
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		want := []Simple{{Argv: []string{"rm", "-rf", "/repo"}, Unresolved: true}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Normalize(%q) = %+v, want %+v", src, got, want)
		}
	}

	got, err := Normalize(`chroot /new-root cat < input > output`)
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

	got, err = Normalize(`chroot /new-root command -v git < input > output`)
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
		got, err := Normalize(c.src)
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

func TestNormalizeUnwrapsAddedShellC(t *testing.T) {
	for _, shell := range []string{"fish", "csh", "tcsh", "mksh", "ash"} {
		src := shell + ` -c "rm -rf /"`
		got, err := Normalize(src)
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
		got, err := Normalize(src)
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
		got, err := Normalize(src)
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
		got, err := Normalize(src)
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
		got, err := Normalize(src)
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 1 || !got[0].Unresolved {
			t.Errorf("Normalize(%q) = %+v, want one unresolved Simple", src, got)
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
		got, err := Normalize(src)
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
		got, err := Normalize(src)
		if err != nil {
			t.Errorf("Normalize(%q): %v", src, err)
			continue
		}
		if len(got) != 0 {
			t.Errorf("Normalize(%q) = %+v, want no Simples", src, got)
		}
	}

	got, err := Normalize(`chroot /new-root command git status`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Simple{{Argv: []string{"git", "status"}, Unresolved: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Normalize chroot positional command = %+v, want %+v", got, want)
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
