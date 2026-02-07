package api

import (
	"testing"

	shellquote "github.com/kballard/go-shellquote"
)

func TestShellQuoteArgsSimple(t *testing.T) {
	got := ShellQuoteArgs([]string{"echo", "hello"})
	if got != "echo hello" {
		t.Errorf("got %q, want %q", got, "echo hello")
	}
}

func TestShellQuoteArgsWithSpaces(t *testing.T) {
	got := ShellQuoteArgs([]string{"echo", "hello world"})
	assertRoundTrips(t, got, []string{"echo", "hello world"})
}

func TestShellQuoteArgsEmpty(t *testing.T) {
	got := ShellQuoteArgs(nil)
	if got != "" {
		t.Errorf("got %q, want empty string", got)
	}
}

func TestShellQuoteArgsSingleArg(t *testing.T) {
	got := ShellQuoteArgs([]string{"ls"})
	if got != "ls" {
		t.Errorf("got %q, want %q", got, "ls")
	}
}

func TestShellQuoteArgsSpecialChars(t *testing.T) {
	assertRoundTrips(t, ShellQuoteArgs([]string{"echo", "$HOME"}), []string{"echo", "$HOME"})
}

func TestShellQuoteArgsSingleQuoteInArg(t *testing.T) {
	assertRoundTrips(t, ShellQuoteArgs([]string{"echo", "it's"}), []string{"echo", "it's"})
}

func TestShellQuoteArgsGlob(t *testing.T) {
	assertRoundTrips(t, ShellQuoteArgs([]string{"ls", "*.go"}), []string{"ls", "*.go"})
}

func TestShellQuoteArgsMixed(t *testing.T) {
	assertRoundTrips(t, ShellQuoteArgs([]string{"sh", "-c", "echo hello && ls -la"}), []string{"sh", "-c", "echo hello && ls -la"})
}

func TestShellQuoteArgsEmptyArg(t *testing.T) {
	assertRoundTrips(t, ShellQuoteArgs([]string{"echo", ""}), []string{"echo", ""})
}

func TestShellQuoteArgsBackslash(t *testing.T) {
	assertRoundTrips(t, ShellQuoteArgs([]string{"echo", `a\b`}), []string{"echo", `a\b`})
}

// assertRoundTrips verifies that the quoted string splits back into the original args.
func assertRoundTrips(t *testing.T, quoted string, want []string) {
	t.Helper()
	got, err := shellquote.Split(quoted)
	if err != nil {
		t.Fatalf("Split(%q): %v", quoted, err)
	}
	if len(got) != len(want) {
		t.Fatalf("Split(%q) = %v (len %d), want %v (len %d)", quoted, got, len(got), want, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Split(%q)[%d] = %q, want %q", quoted, i, got[i], want[i])
		}
	}
}
