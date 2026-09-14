package scanner

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/suseong41/suseong-html-analyzer/tokenizer"
)

// normalizeURL() 브라우저가 실제로 보는 URL 값을 만든다.
// 디코딩 -> 소문자 -> 공백류 제거.
func normalizeURL(v string) string {
	v = tokenizer.Unescape(v)                 // &#106; → j
	v = strings.ToLower(strings.TrimSpace(v)) // JaVaScRiPt: → javascript:
	return strings.Map(func(r rune) rune {    // java\tscript: → javascript:
		if r == '\t' || r == '\n' || r == '\r' || r == '\f' {
			return -1
		}
		return r
	}, v)
}

// isDangerousJSURL() 실제로 코드가 실행되는 javascript: URL만 골라낸다.
func isDangerousJSURL(v string) bool {
	if !strings.HasPrefix(v, "javascript:") {
		return false
	}
	body := strings.Trim(strings.TrimPrefix(v, "javascript:"), "; ")
	return body != "" && body != "void(0)"
}

// inlineHandlerRule(): 인라인 이벤트 핸들러를 한 건으로 묶음.
type inlineHandlerRule struct{ agg aggregator }

func (r *inlineHandlerRule) Check(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken {
		return nil
	}
	for _, a := range tok.Attrs {
		if strings.HasPrefix(a.Name, "on") && 2 < len(a.Name) {
			r.agg.add("*", "<"+tok.Name+" "+a.Name+"=…>", a.Offset)
		}
	}
	return nil
}

func (r *inlineHandlerRule) Finish(ctx *Context) []Finding {
	it := r.agg.items["*"]
	if it == nil {
		return nil
	}
	ev := it.first
	if 1 < it.count {
		ev = fmt.Sprintf("%d곳 (첫 위치: %s)", it.count, it.first)
	}
	return []Finding{{
		Code: "inline-handler", Class: ClassHardening,
		Title: "인라인 이벤트 핸들러", Severity: Low,
		Offset: it.firstOff, Evidence: ev,
	}}
}

// javaScriptURLRule: javascript: URL을 수백개 쓰기에, 묻히지 않도록
type javaScriptURLRule struct{ agg aggregator }

const (
	jsURLPlain  = "평문"
	jsURLHidden = "우회"
)

func (r *javaScriptURLRule) Check(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken {
		return nil
	}
	for _, a := range tok.Attrs {
		if a.Name != "href" && a.Name != "src" {
			continue
		}
		if !isDangerousJSURL(normalizeURL(a.Value)) {
			continue
		}
		key := jsURLPlain
		if !strings.HasPrefix(asciiLower(strings.TrimSpace(a.Value)), "javascript:") {
			key = jsURLHidden // 디코딩해야 드러남
		}
		r.agg.add(key, a.Name+"="+a.Value, a.Offset)
	}
	return nil
}

func (r *javaScriptURLRule) Finish(ctx *Context) []Finding {
	var out []Finding
	for _, key := range r.agg.keys {
		it := r.agg.items[key]
		ev := it.first
		if 1 < it.count {
			ev = fmt.Sprintf("%d곳 (첫 위치: %s)", it.count, it.first)
		}
		title := "javascript: URL"
		if key == jsURLHidden {
			title = "문자 참조로 가린 javascript: URL"
		}
		out = append(out, Finding{
			Code: "javascript-url", Class: ClassExecution,
			Title:    title,
			Severity: Medium,
			Offset:   it.firstOff,
			Evidence: ev,
		})
	}
	return out
}

// -- 제로폭 문자 난독화 (H001) ----

var zeroWidth = map[rune]string{
	'\u200B': "U+200B ZERO WIDTH SPACE",
	'\u200C': "U+200C ZWNJ",
	'\u200D': "U+200D ZWJ",
	'\u2060': "U+2060 WORD JOINER",
	'\uFEFF': "U+FEFF BOM",
}

func findZeroWidth(s string) (string, bool) {
	for i, r := range s {
		name, ok := zeroWidth[r]
		if !ok {
			continue
		}
		prev := lastNonZeroWidth(s[:i])
		next := firstNonZeroWidth(s[i+utf8.RuneLen(r):])
		if zeroWidthLegit(r, prev, next) {
			continue
		}
		return name, true
	}
	return "", false
}

// zeroWidthLegit(): 제로폭 문자가 그 자리에 쓰일 이유가 있는지 확인
func zeroWidthLegit(r, prev, next rune) bool {
	// 단어를 쪼개지 않으면 조판 목적. 하지만 BOM은 조판 용도가 없어 의심.
	if r != '\uFEFF' && (!wordChar(prev) || !wordChar(next)) {
		return true
	}
	switch r {
	case '\u200C', '\u200D': // ZWNJ · ZWJ
		if joiningScript(prev) && joiningScript(next) {
			return true
		}
		return r == '\u200D' && emojiPart(prev) && emojiPart(next)
	}
	return false
}

// lastNonZeroWidth, firstNonZeroWidth(): 제로폭 문자는 건너뛰고 앞뒤 글자를 찾음
func lastNonZeroWidth(s string) rune {
	for 0 < len(s) {
		r, size := utf8.DecodeLastRuneInString(s)
		if _, isZW := zeroWidth[r]; !isZW {
			return r
		}
		s = s[:len(s)-size]
	}
	return utf8.RuneError
}

func firstNonZeroWidth(s string) rune {
	for 0 < len(s) {
		r, size := utf8.DecodeRuneInString(s)
		if _, isZW := zeroWidth[r]; !isZW {
			return r
		}
		s = s[size:]
	}
	return utf8.RuneError
}

// wordChar(): 제로폭 문자가 글자 사이에 끼면 단어를 쪼갠 것.
func wordChar(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// joiningScripts(): 글자가 서로 이어져 쓰이는 문자 체계
var joiningScripts = []*unicode.RangeTable{
	unicode.Arabic, unicode.Syriac, unicode.Thaana, unicode.Nko, unicode.Mongolian,
	unicode.Devanagari, unicode.Bengali, unicode.Gurmukhi, unicode.Gujarati,
	unicode.Oriya, unicode.Tamil, unicode.Telugu, unicode.Kannada, unicode.Malayalam,
	unicode.Sinhala, unicode.Myanmar, unicode.Khmer,
}

func joiningScript(r rune) bool { return unicode.In(r, joiningScripts...) }

// emojiPart(): 이모지, 이모지에 붙는 변이 선택자(U+FE0F)
func emojiPart(r rune) bool {
	switch {
	case r == 0xFE0F:
		return true
	case 0x1F000 <= r && r <= 0x1FAFF:
		return true
	case 0x2600 <= r && r <= 0x27BF:
		return true
	case 0x2B00 <= r && r <= 0x2BFF:
		return true
	}
	return false
}

func zeroWidthFinding(name string, off int, where string) Finding {
	return Finding{
		Code: "zero-width", Class: ClassEvasion,
		Title:    "제로폭 문자 난독화",
		Severity: Low,
		Offset:   off,
		Evidence: where + "에 " + name,
	}
}

func ruleZeroWidth(ctx *Context, tok tokenizer.Token) []Finding {
	switch tok.Type {
	case tokenizer.TextToken:
		if name, ok := findZeroWidth(tok.Data); ok {
			return []Finding{zeroWidthFinding(name, tok.Offset, "텍스트")}
		}
	case tokenizer.StartTagToken:
		for _, a := range tok.Attrs {
			if name, ok := findZeroWidth(a.Value); ok {
				return []Finding{zeroWidthFinding(name, a.Offset, a.Name+" 속성값")}
			}
		}
	}
	return nil
}

// -- 외부 도메인으로 가는 비밀번호 폼 (H103) ----

func ruleCrossOriginPasswordForm(ctx *Context, tok tokenizer.Token) []Finding {
	if ctx.Domain == "" {
		return nil
	}
	var out []Finding
	for _, dst := range ctx.CredentialDestinations() {
		d := absoluteHost(dst.url)
		if d == "" || isSameOrg(d, ctx.Domain) {
			continue
		}
		out = append(out, Finding{
			Code: "cross-origin-password-form", Class: ClassExfiltration,
			Title:    "비밀번호 폼이 외부 도메인으로 전송됨",
			Severity: High,
			Offset:   tok.Offset,
			Evidence: ctx.Domain + " → " + d + "  (" + dst.attr + "=" + dst.url + ")",
		})
	}
	return out
}
