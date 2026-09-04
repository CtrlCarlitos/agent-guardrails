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
