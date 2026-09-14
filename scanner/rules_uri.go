package scanner

import (
	"strings"

	"github.com/suseong41/suseong-html-analyzer/tokenizer"
)

// isIPLiteralHost() 호스트가 IPv4 리터럴인지 확인.
func isIPLiteralHost(host string) bool {
	if strings.HasPrefix(host, "[") { // IPv6
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || 3 < len(p) {
			return false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || '9' < p[i] {
				return false
			}
		}
	}
	return true
}

// 폼을 도메인 없이 ip로 보내는 정상 사이트는 거의 없음
func ruleFormActionIP(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken || tok.Name != "form" {
		return nil
	}
	if !ctx.FormAccepted(tok) {
		return nil // 중첩 form
	}
	action, ok := tok.Attr("action")
	if !ok {
		return nil
	}
	host := absoluteHost(action)
	if !isIPLiteralHost(host) {
		return nil
	}
	return []Finding{{
		Code: "form-action-ip", Class: ClassExfiltration, Title: "폼이 IP 주소로 직접 전송됨",
		Severity: High, Offset: tok.Offset, Evidence: "action=" + action,
	}}
}

// data: URI를 문서로 해석하는 컨텍스트
func isDocumentContext(tag, attr string) bool {
	switch tag {
	case "iframe", "embed", "frame":
		return attr == "src"
	case "object":
		return attr == "data"
	case "a", "area":
		return attr == "href"
	case "script":
		return attr == "src"
	}
	return false
}

// 브라우저가 실행/렌더링하는 data: 타입
var excutableDataTypes = []string{
	"text/html", "application/xhtml+xml", "image/svg+xml",
	"text/javascript", "application/javascript", "application/x-javascript",
	"application/ecmascript", "text/ecmascript",
}

func ruleDataURIDocument(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken {
		return nil
	}
	var out []Finding
	for _, a := range tok.Attrs {
		if !isDocumentContext(tok.Name, a.Name) {
			continue
		}
		v := normalizeURL(a.Value)
		if !strings.HasPrefix(v, "data:") {
			continue
		}
		mime := v[len("data:"):]
		if i := strings.IndexAny(mime, ";,"); 0 <= i {
			mime = mime[:i]
		}
		if mime == "" {
			mime = "text/plain"
		}
		for _, t := range excutableDataTypes {
			if mime == t {
				out = append(out, Finding{
					Code: "data-uri-document", Class: ClassExecution, Title: "실행 가능한 data: URI 를 " + tok.Name + " 에 삽입",
					Severity: High, Offset: a.Offset,
					Evidence: "<" + tok.Name + " " + a.Name + "=data:" + mime + "…>",
				})
				break
			}
		}
	}
	return out
}
