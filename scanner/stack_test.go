package scanner

import (
	"strings"
	"testing"

	"github.com/suseong41/sha/tokenizer"
)

// 입력을 끝까지 읽은 뒤 남은 열린 요소들은 "div>span" 형태로.
func finalStack(html string) string {
	var st openStack
	z := tokenizer.New(html)
	for {
		tok := z.Next()
		if tok.Type == tokenizer.ErrToken {
			break
		}
		switch tok.Type {
		case tokenizer.StartTagToken:
			st.start(tok)
		case tokenizer.EndTagToken:
			st.end(tok.Name)
		}
	}
	return strings.Join(st.names, ">")
}

func TestOpenStack(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"기본중첩", "<div><span>", "div>span"},
		{"정상닫기", "<div><span></span></div>", ""},
		{"void는안쌓임", "<div><img><br><input>", "div"},
		{"div가p를닫음", "<div><p>a<div>", "div>div"},
		{"li형제", "<ul><li>a<li>b", "ul>li"},
		{"li닫기", "<ul><li>a<li>b</ul>", ""},
		{"표", "<table><tr><td>x", "table>tr>td"},
		{"td형제", "<table><tr><td>a<td>b", "table>tr>td"},
		{"짝없는종료태그", "<div></span></p>", "div"},
		{"self-closing무시", "<div/><span>", "div>span"},
		{"option형제", "<select><option>a<option>b", "select>option"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := finalStack(c.in); got != c.want {
				t.Errorf("%q → %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestFormPointer(t *testing.T) {
	cases := []struct{ name, in, wantAction string }{
		{"단순", `<form action="/a"><input>`, "/a"},
		{"중첩은무시", `<form action="/outer"><form action="/inner"><input>`, "/outer"},
		{"닫힌뒤", `<form action="/a"></form>`, ""},
		{"div속", `<form action="/a"><div><p>`, "/a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var st openStack
			z := tokenizer.New(c.in)
			for {
				tok := z.Next()
				if tok.Type == tokenizer.ErrToken {
					break
				}
				switch tok.Type {
				case tokenizer.StartTagToken:
					st.start(tok)
				case tokenizer.EndTagToken:
					st.end(tok.Name)
				}
			}
			got := ""
			if st.form != nil {
				got, _ = st.form.Attr("action")
			}
			if got != c.wantAction {
				t.Errorf("%q → form action %q, want %q", c.in, got, c.wantAction)
			}
		})
	}
}
