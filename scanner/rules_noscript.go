package scanner

import "github.com/suseong41/sha/tokenizer"

// noscriptBreakoutRule: <nosciprt> 안에 숨긴 </noscript>로 빠져나오는 입력
// 의도적 악성행위 일 수 있지만, 오타로도 가능하므로 MEDIUM.
type noscriptBreakoutRule struct {
	cut  bool   // 직전 noscript 내용이 구조 한가운데서 끊겼는가
	tail string // 증거로 보여줄 내용의 끝부분
}

func (r *noscriptBreakoutRule) Check(ctx *Context, tok tokenizer.Token) []Finding {
	switch {
	case tok.Type == tokenizer.TextToken && tok.Raw && ctx.InElement("noscript"):
		z := tokenizer.New(tok.Data)
		for z.Next().Type != tokenizer.ErrToken {
		}
		r.cut = z.Truncated()
		r.tail = excerpt(tok.Data, max(0, len(tok.Data)-40), 40)
	case tok.Type == tokenizer.EndTagToken && tok.Name == "noscript":
		if !r.cut {
			return nil
		}
		r.cut = false
		return []Finding{{
			Code: "noscript-breakout", Class: ClassEvasion,
			Title:    "noscript 안에 숨긴 </noscript> 로 탈출",
			Severity: Medium, Offset: tok.Offset,
			Evidence: "…" + r.tail + "</noscript>",
		}}
	}
	return nil
}
