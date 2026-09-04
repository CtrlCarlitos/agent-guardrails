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
