package scanner

import (
	"strings"

	"github.com/suseong41/suseong-html-analyzer/tokenizer"
)

// destination: 폼이 데이터를 보낼 수 있는 곳 하나.
type destination struct {
	attr string // "action" or "formaction"
	url  string
}

// credentialTracker: 지금 열린 form에 비밀번호가 있는지, form의 formaction들을 모음.
// 비밀번호 입력과 제출은 어느 쪽이 먼저 올지 모름.
type credentialTracker struct {
	formOff  int           // 추적 중인 form의 Offset
	password bool          // 이 form에서 비밀번호 입력을 봤는가
	actions  []destination // 이 form 에서 본 formaction 들
	exposed  []destination // 이번 토큰에서 새로 비밀번호가 도달하게 된 전송지
}

func (c *credentialTracker) observe(ctx *Context, tok tokenizer.Token) {
	c.exposed = nil
	form, ok := ctx.OpenForm()
	if !ok || tok.Type != tokenizer.StartTagToken {
		return
	}
	if form.Offset != c.formOff {
		c.formOff, c.password, c.actions = form.Offset, false, nil // 새 form
	}

	switch {
	case isPasswordInput(tok):
		if c.password {
			return // form 전송지를 이미 알린 경우
		}
		c.password = true
		action, _ := form.Attr("action")
		c.exposed = append(c.exposed, destination{"action", action})
		c.exposed = append(c.exposed, c.actions...) // 비밀번호보다 먼저 온 버튼들
	case isSubmitter(tok):
		v, ok := tok.Attr("formaction")
		if !ok {
			return
		}
		d := destination{"formaction", v}
		c.actions = append(c.actions, d)
		if c.password {
			c.exposed = append(c.exposed, d)
		}
	}
}

func isPasswordInput(tok tokenizer.Token) bool {
	if tok.Name != "input" {
		return false
	}
	v, _ := tok.Attr("type")
	return strings.EqualFold(strings.TrimSpace(v), "password")
}
