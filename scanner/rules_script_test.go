package scanner

import "testing"

func TestWebShellSignature(t *testing.T) {
	const code = "webshell-signature"
	cases := []struct {
		name, html string
		want       int
	}{
		{"스타일은아님", `<style>c99shell</style>`, 0},
		{"본문도아님", `<p>c99shell</p>`, 0},
		{"속성도아님", `<div title="c99shell"></div>`, 0},
		{"스크립트", `<script>var m = "c99shell";</script>`, 1},
		{"대소문자", `<script>var m = "C99Shell";</script>`, 1},
		{"다른시그니처", `<script>ByroeNet</script>`, 1},
		{"정상스크립트", `<script>var x = 1;</script>`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestObfuscatedEval(t *testing.T) {
	const code = "obfuscated-eval"
	cases := []struct {
		name, html string
		want       int
	}{
		{"eval단독", `<script>eval(x)</script>`, 0},
		{"atob단독", `<script>atob(x)</script>`, 0},
		{"eval과atob", `<script>eval(atob(x))</script>`, 1},
		{"eval과unescape", `<script>eval(unescape(x))</script>`, 1},
		{"대문자", `<script>EVAL(ATOB(x))</script>`, 1},
		{"fromCharCode", `<script>eval(String.fromCharCode(97))</script>`, 1},
		{"스타일은아님", `<style>eval(atob(x))</style>`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestExfilChannel(t *testing.T) {
	const page = "https://a.com/"
	const code = "exfil-channel"
	cases := []struct {
		name, html string
		want       int
	}{
		{"스크립트에서전송", `<script>fetch("https://api.telegram.org/bot1/x")</script>`, 1},
		{"폼액션", `<form action="https://api.telegram.org/bot1/x"></form>`, 1},
		{"디스코드", `<script>fetch("https://discord.com/api/webhooks/1")</script>`, 1},
		{"정상폼", `<form action="/login"></form>`, 0},
		{"중첩폼무시", `<form action="/login"><form action="https://api.telegram.org/bot1/x"></form></form>`, 0},
		{"앞폼닫힌뒤", `<form action="/login"></form><form action="https://api.telegram.org/bot1/x"></form>`, 1},
		{"정상스크립트", `<script>fetch("/api/data")</script>`, 0},
		{"본문텍스트는아님", `<p>api.telegram.org</p>`, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, page, code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestSignatureOffset(t *testing.T) {
	const html = "<script>\n  var m = \"c99shell\";\n</script>"
	f, ok := findFirst(html, "", "webshell-signature")
	if !ok {
		t.Fatal("발견되지 않음")
	}
	if f.Line != 2 {
		t.Errorf("Line = %d, want 2", f.Line)
	}
	if f.Col != 12 {
		t.Errorf("Col = %d, want 12", f.Col)
	}
}
