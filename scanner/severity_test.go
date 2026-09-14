package scanner

import "testing"

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
		ok   bool
	}{
		{"info", Info, true},
		{"LOW", Low, true},
		{" medium ", Medium, true},
		{"med", Medium, true},
		{"High", High, true},
		{"critical", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseSeverity(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("ParseSeverity(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	for _, s := range []Severity{Info, Low, Medium, High} {
		got, ok := ParseSeverity(s.String())
		if !ok || got != s {
			t.Errorf("%v → %q → %v,%v", s, s.String(), got, ok)
		}
	}
	if got := Severity(99).String(); got != "?" {
		t.Errorf("Severity(99).String() = %q, want \"?\"", got)
	}
}
func TestSeverityOrder(t *testing.T) {
	order := []Severity{Info, Low, Medium, High}
	for i := 1; i < len(order); i++ {
		if !(order[i-1] < order[i]) {
			t.Errorf("%v < %v 이어야 한다", order[i-1], order[i])
		}
	}
}
