package scanner

import (
	"strings"

	"github.com/suseong41/suseong-html-analyzer/tokenizer"
)

// formDestination(): 토큰이 폼 전송지를 선언하면 (속성 이름, 값) 반환.
func formDestination(ctx *Context, tok tokenizer.Token) (attr, url string, ok bool) {
	if tok.Type != tokenizer.StartTagToken {
		return "", "", false
	}
	switch {
	case tok.Name == "form":
		if !ctx.FormAccepted(tok) {
			return "", "", false // 중첩 form
		}
		attr = "action"
	case isSubmitter(tok):
		if _, owned := ctx.OwnerForm(tok); !owned {
			return "", "", false // form 밖의 버튼은 제출하지 않음.
		}
		attr = "formaction"
	default:
		return "", "", false
	}
	url, ok = tok.Attr(attr)
	return attr, url, ok
}

// isSubmitter(): 누르면 form을 제출하는 요소인가
func isSubmitter(tok tokenizer.Token) bool {
	t, _ := tok.Attr("type")
	t = asciiLower(strings.TrimSpace(t))
	switch tok.Name {
	case "button":
		return t != "button" && t != "reset"
	case "input":
		return t == "submit" || t == "image"
	}
	return false
}

// 비밀번호가 평문으로 전송될 때.
// A. <input type=password>가 존재,
// B. <form> 안에 있을 때,
// C. 그 폼의 전송이 평문일 때.
func ruleClearTextCredentials(ctx *Context, tok tokenizer.Token) []Finding {
	var out []Finding
	for _, dst := range ctx.CredentialDestinations() {
		v := normalizeURL(dst.url)
		var why string
		switch {
		case strings.HasPrefix(v, "http://"):
			why = dst.attr + "=" + dst.url
		case absoluteHost(dst.url) == "" && ctx.Scheme == "http":
			why = "페이지가 http, " + dst.attr + " 이 상대 경로 (" + dst.url + ")"
		default:
			continue
		}
		out = append(out, Finding{
			Code: "cleartext-credentials", Class: ClassExfiltration,
			Title:    "비밀번호가 평문으로 전송됨",
			Severity: Medium, Offset: tok.Offset, Evidence: why,
		})
	}
	return out
}

// 이름은 비밀번호인데 typ이 password가 아닌경우
// 개발자 실수. -Medium
var passwordNameHints = []string{"password", "passwd", "pwd"}

func ruleWeakPasswordField(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken || tok.Name != "input" {
		return nil
	}
	typ := strings.ToLower(strings.TrimSpace(mustAttr(tok, "type")))
	if typ != "" && typ != "text" {
		return nil // password, hidden, email
	}
	for _, key := range []string{"name", "id", "autocomplete"} {
		val := asciiLower(mustAttr(tok, key))
		if val == "" {
			continue
		}
		for _, hint := range passwordNameHints {
			if strings.Contains(val, hint) {
				return []Finding{{
					Code: "weak-password-field", Class: ClassHardening,
					Title:    "비밀번호 필드의 type 이 password 가 아님",
					Severity: Medium, Offset: tok.Offset,
					Evidence: key + "=" + mustAttr(tok, key) + " type=" + typ,
				}}
			}
		}
	}
	return nil
}

func mustAttr(tok tokenizer.Token, name string) string {
	v, _ := tok.Attr(name)
	return v
}

// phishingFlagPage(): CDN이 대상을 피싱으로 분류한 것을 보고 경고로 출력
type phishingFlagPage struct{ inter interstitial }

func (r *phishingFlagPage) Check(ctx *Context, tok tokenizer.Token) []Finding {
	r.inter.observe(ctx, tok)
	return nil
}

func (r *phishingFlagPage) Finish(ctx *Context) []Finding {
	if !r.inter.phishingFlagged() {
		return nil
	}
	return []Finding{{
		Code: "phishing-interstitial", Class: ClassExfiltration,
		Title:    "Cloudflare 가 대상을 피싱으로 분류함",
		Severity: High, Offset: 0,
		Evidence: "제3자(Cloudflare) 판정 — 이 HTML 은 경고 페이지다",
	}}
}

// 자격증명을 로컬 주소로 보내는 폼. 공격은 아니니 MEDIUM
var localHotst = []string{"localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1"}

func ruleLocalCredentialPost(ctx *Context, tok tokenizer.Token) []Finding {
	var out []Finding
	for _, dst := range ctx.CredentialDestinations() {
		if !isLocalDestination(dst.url) {
			continue
		}
		out = append(out, Finding{
			Code: "local-credential-post", Class: ClassHardening,
			Title:    "비밀번호 폼이 로컬 주소로 전송됨",
			Severity: Medium, Offset: tok.Offset, Evidence: dst.attr + "=" + dst.url,
		})
	}
	return out
}

// isLocalDestination(): file:// 이거나 호스트가 루프백인가.
func isLocalDestination(url string) bool {
	if strings.HasPrefix(normalizeURL(url), "file://") {
		return true
	}
	host := absoluteHost(url)
	for _, h := range localHotst {
		if host == h {
			return true
		}
	}
	return false
}
