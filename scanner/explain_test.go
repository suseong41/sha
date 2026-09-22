package scanner

import (
	"strings"
	"testing"
)

// 규칙이 늘면 설명도 늘어야 한다. 표가 규칙과 어긋나면 여기서 걸린다.
func TestEveryRuleExplained(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range ScanURL(allRulesHTML, "https://page.example/").Findings {
		seen[f.Code] = true
	}
	if len(seen) == 0 {
		t.Fatal("표본이 아무 규칙도 못 띄웠다")
	}

	for code := range seen {
		e, ok := Explain(code)
		if !ok {
			t.Errorf("%s: 설명이 없다", code)
			continue
		}
		if strings.TrimSpace(e.Why) == "" {
			t.Errorf("%s: 왜 위험한지가 비었다", code)
		}
		if strings.TrimSpace(e.Fix) == "" {
			t.Errorf("%s: 어떻게 고치는지가 비었다", code)
		}
	}
	// 반대 방향 — 없는 규칙을 설명하고 있지 않은가
	for code := range explanations {
		if !seen[code] {
			t.Errorf("%s: 그런 규칙이 없다 (고아 항목)", code)
		}
	}
}

// 설명은 읽으라고 있는 것이다 — 한 줄짜리도, 논문도 아니어야 한다.
func TestExplanationLength(t *testing.T) {
	for code, e := range explanations {
		if n := len([]rune(e.Why)); n < 40 || 400 < n {
			t.Errorf("%s: 왜 위험한지가 %d자 — 40~400자여야 함", code, n)
		}
		if n := len([]rune(e.Fix)); n < 20 || 400 < n {
			t.Errorf("%s: 어떻게 고치는지가 %d자 — 20~400자여야 함", code, n)
		}
	}
}

func TestExplainUnknownCode(t *testing.T) {
	if _, ok := Explain("그런-규칙-없음"); ok {
		t.Error("없는 코드에 설명이 있다고 한다")
	}
}
