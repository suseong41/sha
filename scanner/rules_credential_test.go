package scanner

import "testing"

func TestCleartextCredentials(t *testing.T) {
	const code = "cleartext-credentials"
	cases := []struct {
		name, html, url string
		want            int
	}{
		// 음성
		{"https상대경로", `<form action="/login"><input type=password></form>`, "https://a.com/", 0},
		{"https절대경로", `<form action="https://a.com/login"><input type=password></form>`, "https://a.com/", 0},
		{"비밀번호없음", `<form action="http://a.com/x"><input type=text></form>`, "https://a.com/", 0},
		{"폼밖", `<input type=password>`, "http://a.com/", 0},
		{"URL모름+상대경로", `<form action="/login"><input type=password></form>`, "", 0},
		{"http페이지지만action은https", `<form action="https://a.com/login"><input type=password></form>`, "http://a.com/", 0},
		// 양성
		{"action이http", `<form action="http://a.com/login"><input type=password></form>`, "https://a.com/", 1},
		{"http페이지+상대경로", `<form action="/login"><input type=password></form>`, "http://a.com/", 1},
		{"http페이지+action없음", `<form><input type=password></form>`, "http://a.com/", 1},
		{"대문자타입", `<form action="http://a.com/x"><input TYPE=PASSWORD></form>`, "https://a.com/", 1},
		{"문자참조우회", `<form action="&#104;ttp://a.com/x"><input type=password></form>`, "https://a.com/", 1},
		{"formaction이http", `<form action="https://a.com/login"><input type=password><button formaction="http://a.com/x">x</button></form>`, "https://a.com/", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, c.url, code); got != c.want {
				t.Errorf("%s (%s) → %d건, want %d건", c.html, c.url, got, c.want)
			}
		})
	}

	// 양성은 어느 경로든 MEDIUM이어야 함.
	// 피해 사이트의 http 로그인 폼 -> 공격자 흔적이 아닌 개발자 실수.
	for _, c := range cases {
		if c.want == 0 {
			continue // 음성
		}
		t.Run("심각도_"+c.name, func(t *testing.T) {
			f, ok := findFirst(c.html, c.url, code)
			if !ok {
				t.Fatal("발견되지 않음")
			}
			if f.Severity != Medium {
				t.Errorf("심각도 = %v, want MEDIUM", f.Severity)
			}
		})
	}
}

func TestWeakPasswordField(t *testing.T) {
	const code = "weak-password-field"
	cases := []struct {
		name, html string
		want       int
	}{
		// 음성
		{"정상비밀번호", `<input type="password" name="password">`, 0},
		{"일반텍스트", `<input type="text" name="username">`, 0},
		{"히든", `<input type="hidden" name="password_token">`, 0},
		{"이메일", `<input type="email" name="email">`, 0},
		{"검색", `<input type="text" name="q">`, 0},
		{"input아님", `<div name="password"></div>`, 0},
		// 양성
		{"type=text", `<input type="text" name="password">`, 1},
		{"type없음", `<input name="passwd">`, 1},
		{"id로", `<input type="text" id="user_pwd">`, 1},
		{"대문자", `<input TYPE="TEXT" NAME="Password">`, 1},
		{"autocomplete", `<input type="text" autocomplete="current-password">`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "https://a.com/", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestCrossOriginStillWorks(t *testing.T) {
	const page = "https://bank.example.com/login"
	cases := []struct {
		html string
		want int
	}{
		{`<form action="https://evil.com/x"><input type=password></form>`, 1},
		{`<form action="/login"><input type=password></form>`, 0},
		{`<form action="https://evil.com/x"><form action="/safe"><input type=password></form></form>`, 1},
		{`<input type=password><form action="https://evil.com/x"></form>`, 0},
	}
	for _, c := range cases {
		if got := countCode(c.html, page, "cross-origin-password-form"); got != c.want {
			t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
		}
	}
}
