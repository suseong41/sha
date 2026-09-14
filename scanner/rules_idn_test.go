package scanner

import "testing"

func TestMixedScriptHost(t *testing.T) {
	const code = "mixed-script-host"
	cases := []struct {
		name, html string
		want       int
	}{
		// 정상 — 한 문자 체계로만 이뤄진 IDN
		{"ASCII", `<a href="https://apple.com/">x</a>`, 0},
		{"한글", `<a href="https://한국.kr/">x</a>`, 0},
		{"한글 punycode", `<a href="https://xn--3e0b707e.kr/">x</a>`, 0},
		{"한자", `<a href="https://日本語.jp/">x</a>`, 0},
		{"한자 punycode", `<a href="https://xn--gmqs0ew0c0z5h.jp/">x</a>`, 0},
		{"독일어 움라우트", `<a href="https://münchen.de/">x</a>`, 0},
		{"독일어 punycode", `<a href="https://xn--mnchen-3ya.de/">x</a>`, 0},
		{"키릴만", `<a href="https://пример.рф/">x</a>`, 0},
		{"상대 경로", `<a href="/board/list">x</a>`, 0},
		// 섞임 — 눈으로 구별할 수 없다
		{"키릴 а + 라틴", `<a href="https://аpple.com/">x</a>`, 1},
		{"키릴 punycode", `<a href="https://xn--pple-43d.com/">x</a>`, 1},
		{"그리스 ο + 라틴", `<a href="https://gοogle.com/">x</a>`, 1},
		{"스크립트 출처", `<script src="https://аpple.com/a.js"></script>`, 1},
		{"같은 호스트 여럿은 1건", `<a href="https://аpple.com/a">x</a><a href="https://аpple.com/b">y</a>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "https://a.com/", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}
