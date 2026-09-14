package scanner

import (
	"strings"
	"testing"
)

func TestRuleJavaScriptURL(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{`<a href="javascript:alert(1)">`, 1},
		{`<a href="JaVaScRiPt:alert(1)">`, 1},
		{`<a href="&#106;avascript:alert(1)">`, 1},
		{`<a href="java&#9;script:alert(1)">`, 1}, // 탭 우회
		{`<a href="javascript:;">`, 0},            // 오탐 제외
		{`<a href="javascript:void(0)">`, 0},      // 오탐 제외
		{`<a href="/normal.html">`, 0},
	}
	for _, c := range cases {
		if got := countCode(c.in, "", "javascript-url"); got != c.want {
			t.Errorf("%s → %d건, want %d건", c.in, got, c.want)
		}
	}
}

// 문자 참조로 가린것만 따로 카운트
func TestJavaScriptURLAggregation(t *testing.T) {
	cases := []struct {
		name, html string
		want       int
	}{
		{"같은 형태 셋", `<a href="javascript:f(1)">a</a><a href="javascript:f(2)">b</a><a href="javascript:f(3)">c</a>`, 1},
		{"평문과 우회는 따로", `<a href="javascript:f(1)">a</a><a href="&#106;avascript:alert(1)">b</a>`, 2},
		{"우회만 여럿", `<a href="&#106;avascript:a()">a</a><a href="java&#9;script:b()">b</a>`, 1},
		{"없음", `<a href="/x">a</a>`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "", "javascript-url"); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

// 문자 참조로 가린 것은 제목으로 구별
func TestJavaScriptURLHiddenTitle(t *testing.T) {
	f, ok := findFirst(`<a href="&#106;avascript:alert(1)">x</a>`, "", "javascript-url")
	if !ok {
		t.Fatal("발견되지 않음")
	}
	if !strings.Contains(f.Title, "문자 참조") {
		t.Errorf("제목이 %q — 우회임이 드러나지 않는다", f.Title)
	}
	plain, _ := findFirst(`<a href="javascript:f()">x</a>`, "", "javascript-url")
	if plain.Title == f.Title {
		t.Errorf("평문과 우회의 제목이 같다: %q", f.Title)
	}
}
