package safetext

import (
	"strings"
	"testing"
)

func TestSingleLineReplacesC0AndC1Controls(t *testing.T) {
	in := "alpha\x00beta\x1fgamma\x7fdelta\u0080epsilon\u009bzeta\u009feta"
	want := "alpha beta gamma delta epsilon zeta eta"
	if got := SingleLine(in); got != want {
		t.Fatalf("SingleLine() = %q, want %q", got, want)
	}
}

func TestSingleLinePreservesPrintableMultilingualAndFormatUnicode(t *testing.T) {
	in := "café 界 مرحبا family:\U0001f468\u200d\U0001f469\u200d\U0001f467"
	if got := SingleLine(in); got != in {
		t.Fatalf("SingleLine() = %q, want %q", got, in)
	}
}

func TestSingleLineNormalizesUnicodeWhitespace(t *testing.T) {
	in := " \t alpha\n\r\u00a0beta\u2003\u2003gamma \v "
	want := "alpha beta gamma"
	if got := SingleLine(in); got != want {
		t.Fatalf("SingleLine() = %q, want %q", got, want)
	}
}

func TestSingleLineDoesNotCapOutput(t *testing.T) {
	in := strings.Repeat("界", 201)
	if got := SingleLine(in); got != in {
		t.Fatalf("SingleLine() returned %d runes, want %d", len([]rune(got)), len([]rune(in)))
	}
}
