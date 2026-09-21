package scanner

import (
	"strings"

	"github.com/suseong41/sha/tokenizer"
)

// metaRefreshURL(): content="0; url=..."에서 URL 부분만 추출.
func metaRefreshURL(content string) string {
	low := asciiLower(content)
	i := strings.Index(low, "url")
	if i < 0 {
		return ""
	}
	rest := strings.TrimLeft(content[i+3:], " \t\r\n\f")
	if !strings.HasPrefix(rest, "=") {
		return ""
	}
	rest = strings.TrimLeft(rest[1:], " \t\r\n\f")
	return strings.Trim(strings.TrimSpace(rest), `'"`)
}

// meta refresh가 data: / javascript: 로 이동하면 피싱, XSS 위험 신호
func ruleMetaRefreshScheme(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken || tok.Name != "meta" {
		return nil
	}
	if v, ok := tok.Attr("http-equiv"); !ok || !strings.EqualFold(strings.TrimSpace(v), "refresh") {
		return nil
	}
	content, _ := tok.Attr("content")
	target := normalizeURL(metaRefreshURL(content))

	var scheme string
	switch {
	case strings.HasPrefix(target, "data:"):
		scheme = "data:"
	case strings.HasPrefix(target, "javascript:"):
		scheme = "javascript:"
	default:
		return nil
	}
	return []Finding{{
		Code: "meta-refresh-scheme", Class: ClassExecution, Title: "meta refresh 가 " + scheme + " 로 이동",
		Severity: High, Offset: tok.Offset, Evidence: "content=" + content,
	}}
}

// <base href>가 외부 도메인이면 페이지의 모든 상대 URL이 그쪽으로 간다.
func ruleBaseHrefExternal(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken || tok.Name != "base" || ctx.Domain == "" {
		return nil
	}
	href, ok := tok.Attr("href")
	if !ok || strings.TrimSpace(href) == "" {
		return nil
	}
	d := absoluteHost(href)
	if d == "" || isSameOrg(d, ctx.Domain) {
		return nil
	}
	return []Finding{{
		Code: "base-href-external", Class: ClassOrigin, Title: "<base href> 가 외부 도메인을 가리킴",
		Severity: High, Offset: tok.Offset,
		Evidence: ctx.Domain + " → " + d + "  (href=" + href + ")",
	}}
}

// allow-script와 allo-same-origin을 함께 주면 sandbox가 무력화된다.
// "sandbox 없음"은 정상 페이지에 너무 흔하다.
func ruleIframeSandboxEscape(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken || tok.Name != "iframe" {
		return nil
	}
	sb, ok := tok.Attr("sandbox")
	if !ok {
		return nil
	}
	var scripts, sameOrigin bool
	for _, t := range strings.Fields(asciiLower(sb)) {
		switch t {
		case "allow-scripts":
			scripts = true
		case "allow-same-origin":
			sameOrigin = true
		}
	}
	if !scripts || !sameOrigin {
		return nil
	}
	return []Finding{{
		Code: "iframe-sandbox-escape", Class: ClassOrigin, Title: "sandbox 가 allow-scripts 와 allow-same-origin 을 함께 허용",
		Severity: Medium, Offset: tok.Offset, Evidence: "sandbox=" + sb,
	}}
}
