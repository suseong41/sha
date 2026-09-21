package scanner

import (
	"strings"

	"github.com/suseong41/sha/tokenizer"
)

// destination: 폼이 데이터를 보낼 수 있는 곳 하나.
type destination struct {
	attr string // "action" or "formaction"
	url  string
}

// credentialTracker: 지금 열린 form에 비밀번호가 있는지, form의 formaction들을 모음.
// 비밀번호 입력과 제출은 어느 쪽이 먼저 올지 모름.
type credentialTracker struct {
	forms   map[int]*formState // form 시작 태그의 Offset -> 그 폼의 상태
	exposed []destination      // 이번 토큰에서 새로 비밀번호가 도달하게 된 전송지
}

// formState: 한 form이 문서 전체에 흩어져 있을 수 있다. (form="id" 원격 연결)
type formState struct {
	password bool          // 이 form에 비밀번호 입력이 있었는가
	actions  []destination // 이 form의 제출 버튼이 선언한 formaction 들
}

func (c *credentialTracker) state(off int) *formState {
	if c.forms == nil {
		c.forms = map[int]*formState{}
	}
	st, ok := c.forms[off]
	if !ok {
		st = &formState{}
		c.forms[off] = st
	}
	return st
}

func (c *credentialTracker) observe(ctx *Context, tok tokenizer.Token) {
	c.exposed = nil
	if tok.Type != tokenizer.StartTagToken {
		return
	}
	form, ok := ctx.OwnerForm(tok)
	if !ok {
		return
	}
	st := c.state(form.Offset)

	switch {
	case isPasswordInput(tok):
		if st.password {
			return // form 전송지 이미 알음.
		}
		st.password = true
		action, _ := form.Attr("action")
		c.exposed = append(c.exposed, destination{"action", action})
		c.exposed = append(c.exposed, st.actions...) // 비밀번호보다 먼저 온 버튼
	case isSubmitter(tok):
		v, ok := tok.Attr("formaction")
		if !ok {
			return
		}
		d := destination{"formaction", v}
		st.actions = append(st.actions, d)
		if st.password {
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
