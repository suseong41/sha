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
var scriptSignatures = []struct{ needle, name string }{
	{"c99shell", "c99 Shell"},
	{"ls_reserved_all", "c99 Shell"},
	{"byroenet", "ByroeNet Shell"},
	{"r57shell", "r57 Shell"},
}

func ruleWebShellSignature(ctx *Context, tok tokenizer.Token) []Finding {
	data, ok := scriptText(ctx, tok)
	if !ok {
		return nil
	}
	low := asciiLower(data)
	var out []Finding
	for _, sig := range scriptSignatures {
		i := strings.Index(low, sig.needle)
		if i < 0 {
			continue
		}
		out = append(out, Finding{
			Code: "webshell-signature", Class: ClassExecution, Title: "웹셸 시그니처: " + sig.name, Severity: High,
			Offset: tok.Offset + i, Evidence: excerpt(data, i, 48),
		})
	}
	return out
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
	if tok.Type == tokenizer.StartTagToken && tok.Name == "form" && ctx.FormAccepted(tok) {
		action, _ := tok.Attr("action")
		low := asciiLower(normalizeURL(action))
		for _, h := range exfilHosts {
			if strings.Contains(low, h) {
				return []Finding{{
					Code: "exfil-channel", Class: ClassExfiltration, Title: "폼이 외부 메시징 API 로 전송됨", Severity: High,
					Offset: tok.Offset, Evidence: "action=" + action,
				}}
			}
		}
	}
	return nil
}

// eval()이 디코더와 함께일 때 의심
var decoders = []string{"atob(", "unescape(", "fromcharcode(", "decodeuricomponent("}

func ruleObfuscateEval(ctx *Context, tok tokenizer.Token) []Finding {
	data, ok := scriptText(ctx, tok)
	if !ok {
		return nil
	}
	low := asciiLower(data)
	at := strings.Index(low, "eval(")
	if at < 0 {
		return nil
	}
	for _, d := range decoders {
		if strings.Contains(low, d) {
			return []Finding{{
				Code: "obfuscated-eval", Class: ClassEvasion, Title: "eval() 과 디코더 조합", Severity: Medium,
				Offset: tok.Offset + at, Evidence: "eval( + " + strings.TrimSuffix(d, "("),
			}}
		}
	}
	return nil
}
