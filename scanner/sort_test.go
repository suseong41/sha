package scanner

import "testing"

func TestSortBySeverity(t *testing.T) {
	fs := []Finding{
		{Code: "a", Severity: Low},
		{Code: "b", Severity: Medium},
		{Code: "c", Severity: High},
		{Code: "d", Severity: Medium},
	}
	SortBySeverity(fs)
	want := []string{"c", "b", "d", "a"}
	for i, f := range fs {
		if f.Code != want[i] {
			t.Fatalf("순서가 %v — 원하는 값: %v", codes(fs), want)
		}
	}
}

func codes(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Code
	}
	return out
}
