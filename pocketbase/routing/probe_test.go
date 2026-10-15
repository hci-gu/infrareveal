package routing

import "testing"

func TestParserRejectsIncompleteTimingAndPreservesUnreachable(t *testing.T) {
	if got := parseHops([]byte("\n 1  1.1.1.1  1.")); len(got) != 0 {
		t.Fatal(got)
	}
	got := parseHops([]byte("\n 1  1.1.1.1  1.0 ms !X"))
	if len(got) != 1 || got[0].State != "unreachable" {
		t.Fatal(got)
	}
}
