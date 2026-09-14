package scanner

import "testing"

func TestIsIPLiteralHost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"1.2.3.4", true}, {"192.168.0.1", true}, {"[::1]", true},
		{"example.com", false}, {"1.2.3", false}, {"1.2.3.4.5", false},
		{"a.b.c.d", false}, {"1234.1.1.1", false}, {"", false},
		{"1.2.3.", false},
	}
	for _, c := range cases {
		if got := isIPLiteralHost(c.in); got != c.want {
			t.Errorf("isIPLiteralHost(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestFormActionIP(t *testing.T) {
	const page = "https://a.com/"
	const code = "form-action-ip"
	cases := []struct {
		name, html string
		want       int
	}{
		{"상대경로", `<form action="./Default.aspx"></form>`, 0},
		{"도메인", `<form action="https://b.com/p"></form>`, 0},
		{"action없음", `<form></form>`, 0},
		{"경로에숫자", `<form action="/api/1.2.3.4/x"></form>`, 0},
		{"IP주소", `<form action="http://192.168.0.1/steal"></form>`, 1},
		{"IP포트", `<form action="https://203.0.113.5:8080/x"></form>`, 1},
		{"스킴리스IP", `<form action="//203.0.113.5/x"></form>`, 1},
		// 중첩 form 은 브라우저가 무시한다 — 전송되지 않는 action 이다
		{"중첩form무시", `<form action="/ok"><form action="http://192.168.0.1/x"></form></form>`, 0},
		{"바깥이IP", `<form action="http://192.168.0.1/x"><form action="/ok"></form></form>`, 1},
		{"앞form닫힌뒤", `<form action="/ok"></form><form action="http://192.168.0.1/x"></form>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, page, code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}

}

func TestDataURIDocument(t *testing.T) {
	const code = "data-uri-document"
	cases := []struct {
		name, html string
		want       int
	}{
		// 음성 — 정상적으로 흔한 사용
		{"이미지", `<img src="data:image/png;base64,iVBORw0KGgo=">`, 0},
		{"빈플레이스홀더", `<img src="data:image/jpeg;base64,">`, 0},
		{"폰트", `<style>@font-face{src:url(data:font/woff2;base64,AA)}</style>`, 0},
		{"일반URL", `<iframe src="https://x.com/"></iframe>`, 0},
		{"iframe이미지", `<iframe src="data:image/png;base64,AA"></iframe>`, 0},
		// 양성
		{"iframe에HTML", `<iframe src="data:text/html;base64,PHNjcmlwdD4="></iframe>`, 1},
		{"object", `<object data="data:text/html,<script>alert(1)</script>"></object>`, 1},
		{"embed", `<embed src="data:image/svg+xml,%3Csvg%3E">`, 1},
		{"a링크", `<a href="data:text/html,x">click</a>`, 1},
		{"script", `<script src="data:text/javascript,alert(1)"></script>`, 1},
		{"대문자", `<IFRAME SRC="DATA:TEXT/HTML,x"></IFRAME>`, 1},
		{"문자참조우회", `<iframe src="&#100;ata:text/html,x"></iframe>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "https://a.com/", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}
