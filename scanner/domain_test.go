package scanner

import (
	"strings"
	"testing"
)

func TestRegistrableDomain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"www.lotteon.com", "lotteon.com"},
		{"static.lotteon.com", "lotteon.com"},
		{"lotteon.com", "lotteon.com"},
		{"www.seoul.go.kr", "seoul.go.kr"},
		{"a.b.c.seoul.go.kr", "seoul.go.kr"},
		{"www.11st.co.kr", "11st.co.kr"},
		{"github.githubassets.com", "githubassets.com"},
		{"go.dev", "go.dev"},
		{"127.0.0.1", "127.0.0.1"},
		{"localhost", "localhost"},
		{"co.kr", "co.kr"},
		{"attacker.github.io", "attacker.github.io"},
		{"github.io", "github.io"},
		{"shop-abc.vercel.app", "shop-abc.vercel.app"},
		{"d111111abcdef8.cloudfront.net", "d111111abcdef8.cloudfront.net"},
		{"www.seoul.kr", "www.seoul.kr"},
		{"", ""},
	}
	for _, c := range cases {
		if got := registrableDomain(c.in); got != c.want {
			t.Errorf("registrableDomain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSameOrgDoesNotOverMerge(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{

		{"www.lotteon.com", "static.lotteon.com", true},
		{"www.seoul.go.kr", "data.seoul.go.kr", true},
		{"a.co.kr", "b.co.kr", false}, // ← 표가 없으면 true 가 되어 미탐
		{"a.go.kr", "b.go.kr", false},
		{"github.com", "github.githubassets.com", false},
		// 같은 호스팅이라도 계정이 다르면 남이다 — 표가 없으면 true 가 되어 미탐
		{"victim.github.io", "attacker.github.io", false},
		{"shop-abc.vercel.app", "steal-xyz.vercel.app", false},
		{"a.netlify.app", "b.netlify.app", false},
		{"www.seoul.kr", "evil.seoul.kr", false},
		{"victim.github.io", "victim.github.io", true}, // 같은 계정은 같은 조직
		{"a.com", "", false},
	}
	for _, c := range cases {
		if got := isSameOrg(c.a, c.b); got != c.want {
			t.Errorf("isSameOrg(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestSRIAggregation(t *testing.T) {
	const page = "https://a.com/"
	cases := []struct {
		name, html string
		want       int
	}{
		{"같은조직서브도메인", `<script src="https://static.a.com/1.js"></script>`, 0},
		{"integrity있음", `<script src="//cdn.x.com/a.js" integrity="sha384-a"></script>`, 0},
		{"외부1종", `<script src="//cdn.x.com/1.js"></script>`, 1},
		{"같은호스트3개는1건", `<script src="//cdn.x.com/1.js"></script>` +
			`<script src="//cdn.x.com/2.js"></script><script src="//cdn.x.com/3.js"></script>`, 1},
		{"호스트2종은2건", `<script src="//cdn.x.com/1.js"></script><script src="//cdn.y.com/1.js"></script>`, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, page, "sri-missing"); got != c.want {
				t.Errorf("%d건, want %d건", got, c.want)
			}
		})
	}
}

func TestInlineHandlerAggregation(t *testing.T) {
	cases := []struct {
		name, html string
		want       int
	}{
		{"없음", `<p>x</p>`, 0},
		{"1개", `<a onclick="x()">z</a>`, 1},
		{"100개도1건", strings.Repeat(`<a onclick="x()">z</a>`, 100), 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "https://a.com/", "inline-handler"); got != c.want {
				t.Errorf("%d건, want %d건", got, c.want)
			}
		})
	}
}
