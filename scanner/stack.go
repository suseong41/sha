package scanner

import "github.com/suseong41/sha/tokenizer"

var voidElments = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true,
	"hr": true, "img": true, "input": true, "link": true, "meta": true,
	"param": true, "source": true, "track": true, "wbr": true,
}

// p 닫는 욧소들
var closesP = map[string]bool{
	"address": true, "article": true, "aside": true, "blockquote": true,
	"details": true, "div": true, "dl": true, "fieldset": true,
	"figcaption": true, "figure": true, "footer": true, "form": true,
	"h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true,
	"header": true, "hgroup": true, "main": true, "menu": true,
	"nav": true, "ol": true, "p": true, "pre": true, "section": true,
	"table": true, "ul": true,
}

// 형제가 열리면 스스로 닫히는 요소들.
var autoClose = map[string][]string{
	"li":       {"li"},
	"dt":       {"dt", "dd"},
	"dd":       {"dt", "dd"},
	"option":   {"option"},
	"optgroup": {"option", "optgroup"},
	"tr":       {"tr", "td", "th"},
	"td":       {"td", "th"},
	"th":       {"td", "th"},
	"thead":    {"tbody", "tfoot", "thead"},
	"tbody":    {"tbody", "tfoot", "thead"},
	"tfoot":    {"tbody", "tfoot", "thead"},
}

type openStack struct {
	names []string
	form  *tokenizer.Token // form element pointer
}

func (s *openStack) start(tok tokenizer.Token) {
	name := tok.Name

	if closesP[name] {
		s.popTo("p")
	}
	for _, sibling := range autoClose[name] {
		if s.top() == sibling {
			s.pop()
			break
		}
	}

	if name == "form" {
		if s.form != nil {
			return // 중첩 form 무시
		}
		t := tok
		s.form = &t
	}

	if voidElments[name] {
		return
	}
	s.names = append(s.names, name)
}

func (s *openStack) end(name string) {
	if name == "form" {
		s.form = nil
	}
	s.popTo(name)
}

// popTo(): name이 열려있으면 그것까지 팝.
func (s *openStack) popTo(name string) {
	for i := len(s.names) - 1; 0 <= i; i-- {
		if s.names[i] == name {
			s.names = s.names[:i]
			return
		}
	}
}

func (s *openStack) top() string {
	if len(s.names) == 0 {
		return ""
	}
	return s.names[len(s.names)-1]
}

func (s *openStack) pop() {
	if 0 < len(s.names) {
		s.names = s.names[:len(s.names)-1]
	}
}

func (s *openStack) has(name string) bool {
	for _, n := range s.names {
		if n == name {
			return true
		}
	}
	return false
}
