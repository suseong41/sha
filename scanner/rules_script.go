package scanner

import (
	"strings"

	"github.com/suseong41/suseong-html-analyzer/tokenizer"
)

// asciiLower(): ASCII만 소문자로 변환. 바이트 길이 보존
// sting.ToLower()은 유니코드를 처리해 바이트 길이 변동 가능.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// excerpt(): 발견 지점 주변을 한줄로 표기
func excerpt(s string, at, n int) string {
	if at < 0 || len(s) <= at {
		return ""
	}
	end := at + n
	if len(s) < end {
		end = len(s)
	}
	out := strings.ToValidUTF8(s[at:end], "")
	return strings.Join(strings.Fields(out), " ")
}

// scriptText(): <script> 안의 텍스트일 때만 내용 표기
func scriptText(ctx *Context, tok tokenizer.Token) (string, bool) {
	if tok.Type != tokenizer.TextToken || !ctx.InElement("script") {
		return "", false
	}
	return tok.Data, true
}

// 알려진 웹셸 시그니처
var webShellSignatures = []struct{ needle, name string }{
	{"c99shell", "c99 Shell"},
	{"ls_reserved_all", "c99 Shell"},
	{"byroenet", "ByroeNet Shell"},
	{"r57shell", "r57 Shell"},
}

// 웹셸 화면: 보이는 글에 웹셸 이름 ^ 파일 업로드 칸
type webShellPage struct {
	name     string
	offset   int
	evidence string
	upload   bool
}

func (r *webShellPage) Check(ctx *Context, tok tokenizer.Token) []Finding {
	switch tok.Type {
	case tokenizer.StartTagToken:
		if tok.Name == "input" && asciiLower(mustAttr(tok, "type")) == "file" {
			r.upload = true
		}
	case tokenizer.TextToken:
		if tok.Raw || r.name != "" {
			return nil
		}
		low := asciiLower(tok.Data)
		for _, sig := range webShellSignatures {
			if i := strings.Index(low, sig.needle); 0 <= i {
				r.name, r.offset, r.evidence = sig.name, tok.Offset+i, excerpt(tok.Data, i, 48)
				break
			}
		}
	}
	return nil
}

func (r *webShellPage) Finish(ctx *Context) []Finding {
	if r.name == "" || !r.upload {
		return nil
	}
	return []Finding{{
		Code: "webshell-signature", Class: ClassExecution, Title: "웹셸 시그니처: " + r.name, Severity: High,
		Offset: r.offset, Evidence: r.evidence + " + 파일 업로드 칸",
	}}
}

var exfilHosts = []string{
	"api.telegram.org",
	"discord.com/api",
	"discordapp.com/api",
	"hooks.slack.com",
}

func ruleExfilChannel(ctx *Context, tok tokenizer.Token) []Finding {
	if data, ok := scriptText(ctx, tok); ok {
		low := asciiLower(data)
		for _, h := range exfilHosts {
			if i := strings.Index(low, h); 0 <= i {
				return []Finding{{
					Code: "exfil-channel", Class: ClassExfiltration, Title: "스크립트가 외부 메시징 API 로 전송", Severity: High,
					Offset: tok.Offset + i, Evidence: excerpt(data, i, 60),
				}}
			}
		}
		return nil
	}
	if attr, action, ok := formDestination(ctx, tok); ok {
		low := asciiLower(normalizeURL(action))
		for _, h := range exfilHosts {
			if strings.Contains(low, h) {
				return []Finding{{
					Code: "exfil-channel", Class: ClassExfiltration, Title: "폼이 외부 메시징 API 로 전송됨", Severity: High,
					Offset: tok.Offset, Evidence: attr + "=" + action,
				}}
			}
		}
	}
	return nil
}

// eval()이 디코더와 함께일 때 의심
var decoders = []string{"atob(", "unescape(", "fromcharcode(", "decodeuricomponent("}

// evalArgument(): from 이후 첫 eval( 의 인자 범위를 괄호 균형으로 찾음.
func evalArgument(low string, from int) (arg string, at int, ok bool) {
	i := strings.Index(low[from:], "eval(")
	if i < 0 {
		return "", -1, false
	}
	at = from + i
	start := at + len("eval(")
	depth := 1
	for j := start; j < len(low); j++ {
		switch low[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return low[start:j], at, true
			}
		}
	}
	return "", at, false
}

// eval에 디코더를 먹이는 것만 봄
func ruleObfuscateEval(ctx *Context, tok tokenizer.Token) []Finding {
	data, ok := scriptText(ctx, tok)
	if !ok {
		return nil
	}
	low := asciiLower(data)
	for from := 0; from < len(low); {
		arg, at, closed := evalArgument(low, from)
		if at < 0 {
			break
		}
		from = at + len("eval(")
		if !closed {
			continue
		}
		for _, d := range decoders {
			if strings.Contains(arg, d) {
				return []Finding{{
					Code: "obfuscated-eval", Class: ClassEvasion,
					Title:    "eval() 인자에 디코더",
					Severity: Medium,
					Offset:   tok.Offset + at,
					Evidence: "eval(" + excerpt(arg, 0, 40) + ")",
				}}
			}
		}
	}
	return nil
}
