package scanner

import (
	"testing"
	"unicode/utf8"
)

func TestPunyDecode(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		// RFC 3492 예시와 실제 도메인
		{"xn--mnchen-3ya", "münchen", true},
		{"xn--fiqs8s", "中国", true},
		{"xn--80akhbyknj4f", "испытание", true},
		{"xn--n3h", "☃", true},
		{"xn--gmqs0ew0c0z5h", "人名辞典", true}, // 日本語.jp 에서 실제로 본 것
		{"xn--i5wq75dpjj", "渋谷駅", true},
		{"xn--3e0b707e", "한국", true},
		{"xn--pple-43d", "аpple", true}, // 키릴 а + 라틴 pple — 혼동 공격
		// punycode 가 아니면 그대로
		{"example", "example", true},
		{"muenchen", "muenchen", true},
		// 되돌릴 수 없는 것
		{"xn--", "", false},
		{"xn--!!", "", false},
		{"xn--a-#", "", false},
	}
	for _, c := range cases {
		got, ok := punyDecode(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("punyDecode(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func FuzzPunyDecode(f *testing.F) {
	for _, s := range []string{"mnchen-3ya", "fiqs8s", "n3h", "pple-43d", "", "-", "----",
		"zzzzzzzzzzzzzzzzzzzzzzzz", "99999999999999999999", "a-b-c-d"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, ok := punyDecode("xn--" + s)
		if !ok {
			return
		}
		if !utf8.ValidString(out) {
			t.Fatalf("유효하지 않은 UTF-8: %q → %q", s, out)
		}
		if n := utf8.RuneCountInString(out); len(s) < n {
			t.Fatalf("입력보다 긴 출력: %q(%d바이트) → %d글자", s, len(s), n)
		}
	})
}
