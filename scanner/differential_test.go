package scanner

import "testing"

// 브라우저와 해석이 갈리는 입력
func TestParserDifferential(t *testing.T) {
	cases := []struct {
		name, html, code string
	}{
		// 스크립트가 켜진 브라우저: <noscript> 는 첫 </noscript> 에서 끝난다
		{"noscript속성값탈출", `<noscript><p title="</noscript><img src=x onerror=alert(1)>"></p></noscript>`, "inline-handler"},
		{"noscript링크탈출", `<noscript><a title="</noscript><a href=javascript:alert(1)>x</a>">y</a></noscript>`, "javascript-url"},
		{"noscript속style탈출", `<noscript><style></noscript><img src=x onerror=alert(1)></style></noscript>`, "inline-handler"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if countCode(c.html, "https://a.com/", c.code) == 0 {
				t.Errorf("%s 가 보이지 않음: %s", c.code, c.html)
			}
		})
	}
}
