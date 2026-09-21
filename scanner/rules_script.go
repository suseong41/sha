package scanner

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/suseong41/sha/tokenizer"
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

// scriptText(): 코드 블록인 <script> 안의 텍스트일 때만 내용 표기
func scriptText(ctx *Context, tok tokenizer.Token) (string, bool) {
	if tok.Type != tokenizer.TextToken || !ctx.InElement("script") || !ctx.scriptCode {
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

// 이름을 모르는 웹셸 화면이 보여 주는 PHP 안전 모드 상태
var safeModeMarks = []string{"safe_mode", "safe-mode"}

// 웹셸 화면: 보이는 글에 웹셸 이름 ^ 파일 업로드 칸
type webShellPage struct {
	name     string
	offset   int
	evidence string
	upload   bool
	safeMode bool
	safeAt   int
	safeEv   string
	dirPerm  bool
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

		if !r.safeMode {
			for _, m := range safeModeMarks {
				if i := strings.Index(low, m); 0 <= i {
					r.safeMode, r.safeAt, r.safeEv = true, tok.Offset+i, excerpt(tok.Data, i, 48)
					break
				}
			}
		}
		if strings.Contains(low, "drwx") {
			r.dirPerm = true
		}
	}
	return nil
}

func (r *webShellPage) Finish(ctx *Context) []Finding {
	if !r.upload {
		return nil
	}
	f := Finding{Code: "webshell-signature", Class: ClassExecution, Severity: High}
	switch {
	case r.name != "":
		f.Title, f.Offset, f.Evidence = "웹셸 시그니처: "+r.name, r.offset, r.evidence+" + 파일 업로드 칸"
	case r.safeMode && r.dirPerm:
		f.Title, f.Offset, f.Evidence = "웹셸 화면: 이름 모름", r.safeAt, r.safeEv+" + 디렉터리 권한 + 파일 업로드 칸"
	default:
		return nil
	}
	return []Finding{f}
}

// 방문자 PC의 파일·프로세스를 다루는 Windows 객체
var localObjects = []string{
	"wscript.shell",
	"shell.application",
	"scripting.filesystemobject",
	"adodb.stream",
}

// 실행되는 스크립트가 로컬 시스템 객체를 만듦 -> 드롭퍼·다운로더
type localObjectRule struct {
	found bool // 한 페이지 한 건
}

func (r *localObjectRule) Check(ctx *Context, tok tokenizer.Token) []Finding {
	data, ok := scriptText(ctx, tok)
	if !ok || r.found {
		return nil
	}
	low := asciiLower(data)
	for _, obj := range localObjects {
		if i := strings.Index(low, obj); 0 <= i {
			r.found = true
			return []Finding{{
				Code: "local-system-object", Class: ClassExecution, Title: "스크립트가 방문자 PC 의 파일·프로세스 객체를 만듦", Severity: High,
				Offset: tok.Offset + i, Evidence: excerpt(data, i, 48),
			}}
		}
	}
	return nil
}

// codeScript(): script 블록이 코드인지. 빈 type · JS · VBScript 만
func codeScript(typ string) bool {
	switch asciiLower(strings.TrimSpace(typ)) {
	case "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript",
		"application/x-javascript", "text/x-javascript", "text/jscript", "text/vbscript", "text/vbs":
		return true
	}
	return false
}

// %uXXXX 이스케이프가 이어진 구간. unescape()는 소문자 u만 푼다.
var percentU = regexp.MustCompile(`(?:%u[0-9a-fA-F]{4})+`)

// 셸코드: 실행되는 스크립트의 %u 이스케이프가 글자가 아닌 값으로 풀림
type shellcodeRule struct {
	found bool
}

func (r *shellcodeRule) Check(ctx *Context, tok tokenizer.Token) []Finding {
	data, ok := scriptText(ctx, tok)
	if !ok || r.found {
		return nil
	}
	for _, loc := range percentU.FindAllStringIndex(data, -1) {
		if binaryRun(data[loc[0]:loc[1]]) {
			r.found = true
			return []Finding{{
				Code: "encoded-shellcode", Class: ClassExecution, Title: "스크립트가 %u 로 숨긴 이진 코드(셸코드)", Severity: High,
				Offset: tok.Offset + loc[0], Evidence: excerpt(data, loc[0], 48),
			}}
		}
	}
	return nil
}

// binaryRun(): %u 구간을 풀었을 때 글자가 아닌 값이 있는지
func binaryRun(run string) bool {
	var units []uint16
	for i := 0; i+6 <= len(run); i += 6 {
		v, _ := strconv.ParseUint(run[i+2:i+6], 16, 16)
		units = append(units, uint16(v))
	}
	for i := 0; i < len(units); i++ {
		r := rune(units[i])
		if utf16.IsSurrogate(r) {
			if i+1 == len(units) {
				return true
			}
			r = utf16.DecodeRune(r, rune(units[i+1]))
			if r == unicode.ReplacementChar {
				return true
			}
			i++
		}
		if !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cf) {
			return true
		}
	}
	return false
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
