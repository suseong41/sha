package scanner

import (
	"strings"
	"unicode"

	"github.com/suseong41/sha/tokenizer"
)

// 눈으로 구별할 수 없는 문자 체계 혼합 구분. ex) 라틴 a 키릴 a
var confusableScripts = []struct {
	name  string
	table *unicode.RangeTable
}{
	{"라틴", unicode.Latin},
	{"키릴", unicode.Cyrillic},
	{"그리스", unicode.Greek},
}

// mixedScriptLabel(): 한 라벨에 혼동되는 문자 체계가 섞였는지.
func mixedScriptLabel(label string) ([]string, bool) {
	var found []string
	for _, sc := range confusableScripts {
		if strings.ContainsFunc(label, func(r rune) bool { return unicode.Is(sc.table, r) }) {
			found = append(found, sc.name)
		}
	}
	return found, 1 < len(found)
}

// mixedScriptHost(): 호스트의 라벨 중 하나라도 섞인 경우 그 라벨 반환
func mixedScriptHost(host string) (string, []string, bool) {
	for _, label := range strings.Split(host, ".") {
		decoded, ok := punyDecode(label)
		if !ok {
			continue
		}
		if names, mixed := mixedScriptLabel(decoded); mixed {
			return decoded, names, true
		}
	}
	return "", nil, false
}

// idnHomographRule: 한 라벨에 모양이 같은 문자 체계가 섞인 호스트.
type idnHomographRule struct{ agg aggregator }

func (r *idnHomographRule) Check(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken {
		return nil
	}
	for _, a := range tok.Attrs {
		switch a.Name {
		case "href", "src", "srcset", "action", "formaction", "data", "poster":
		default:
			continue
		}
		host := absoluteHost(a.Value)
		if host == "" {
			continue
		}
		if label, scripts, mixed := mixedScriptHost(host); mixed {
			r.agg.add(host, host+" — 라벨 \""+label+"\" 에 "+strings.Join(scripts, "+")+" 문자가 섞임", a.Offset)
		}
	}
	return nil
}

func (r *idnHomographRule) Finish(ctx *Context) []Finding {
	var out []Finding
	for _, host := range r.agg.keys {
		it := r.agg.items[host]
		out = append(out, Finding{
			Code: "mixed-script-host", Class: ClassOrigin,
			Title:    "호스트 이름에 모양이 같은 다른 문자 체계가 섞임",
			Severity: High, Offset: it.firstOff, Evidence: it.first,
		})
	}
	return out
}
