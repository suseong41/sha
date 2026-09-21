package scanner

import (
	"strings"

	"github.com/suseong41/sha/tokenizer"
)

// interstitial(): 지금 보고 있는 HTML이 대상 사이트가 아닌 중간 페이지인지 확인.
type interstitial struct {
	cloudflare  bool
	rayID       bool
	blockPhrase bool
	phishTitle  bool
}

var blockPhrases = []string{
	"attention required", "access denied", "checking your browser",
	"error 1020", "error 1015", "error 1016", "error 1010",
}

func (v *interstitial) observe(ctx *Context, tok tokenizer.Token) {
	if tok.Type != tokenizer.TextToken || tok.Raw {
		return
	}
	low := asciiLower(tok.Data)

	if ctx.InElement("title") {
		if strings.Contains(low, "suspected phishing") && strings.Contains(low, "cloudflare") {
			v.phishTitle = true
		}
	}
	if strings.Contains(low, "cloudflare") {
		v.cloudflare = true
	}
	if strings.Contains(low, "ray id") || strings.Contains(low, "ray-id") {
		v.rayID = true
	}
	for _, p := range blockPhrases {
		if strings.Contains(low, p) {
			v.blockPhrase = true
			break
		}
	}
}

// blocked(): WAF 차단 페이지인지
func (v *interstitial) blocked() bool {
	return v.cloudflare && v.rayID && v.blockPhrase
}

// phishingFlagged(): CDN이 피싱으로 분류했는지
func (v *interstitial) phishingFlagged() bool { return v.phishTitle }

func (v *interstitial) notes() []string {
	switch {
	case v.phishingFlagged():
		return []string{"이 HTML 은 대상 사이트가 아니라 Cloudflare 피싱 경고 페이지다. " +
			"다른 발견은 모두 그 경고 페이지에 대한 것이다."}
	case v.blocked():
		return []string{"이 HTML 은 대상 사이트가 아니라 WAF 차단 페이지다. " +
			"스캐너가 차단되었으므로 대상 페이지는 분석되지 않았다."}
	}
	return nil
}
