package tokenizer

import "testing"

// 입력이 구조 한가운데서 끝났는지. -> 브라우저가 버림.
func TestTruncated(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// 끝까지 닫힘
		{``, false},
		{`<img src=a.png>`, false},
		{`<p>글자`, false}, // 닫는 태그가 없는 건 구조가 끊긴 게 아니다
		{`a < b`, false},
		{`</`, false},
		{`<p title=">">`, false},
		{`<style></style>`, false},
		{`<!-- a -->`, false},
		{`<!doctype html>`, false},
		// 태그 · 속성 한가운데
		{`<p`, true},
		{`<p `, true},
		{`</p`, true},
		{`<p title="`, true},
		{`<p title=">`, true},
		{`<p title='a>b`, true},
		{`<p title=x`, true},
		// 원시 텍스트 요소 한가운데
		{`<style>`, true},
		{`<style>a{}`, true},
		{`<script>var a`, true},
		{`<noscript>`, true},
		// 주석 · 선언 한가운데
		{`<!-- a`, true},
		{`<!x`, true},
		{`<!doctype html`, true},
	}
	for _, c := range cases {
		z := New(c.in)
		for z.Next().Type != ErrToken {
		}
		if got := z.Truncated(); got != c.want {
			t.Errorf("%q → Truncated()=%v, want %v", c.in, got, c.want)
		}
	}
}
