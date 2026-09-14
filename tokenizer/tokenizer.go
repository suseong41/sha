package tokenizer

import (
	"sort"
	"unicode/utf8"
)

type TokenType int

/*
iota 0부터 1씩 증가.
C에 Default enumerate 느낌.
*/
const (
	ErrToken      TokenType = iota // 0
	TextToken                      // 1
	StartTagToken                  // 2 <p>
	EndTagToken                    // 3 </p>
	CommentToken                   // 4 <!-- -->, <!DOCTYPE
	DoctypeToken                   // 5 <!DOCTYPE html>
)

type Token struct {
	Type        TokenType
	Name        string
	Attrs       []Attribute
	Data        string
	Offset      int
	Raw         bool // <script>/<style> 내부 텍스트
	SelfClosing bool
}

type Tokenizer struct {
	buf        []byte // 입력 전체
	pos        int
	rawTag     string // "": 일반 모드, "script": 원시 모드
	lineStarts []int  // 각 줄이 시작하는 오프셋
}

type Attribute struct {
	Name   string
	Value  string
	Quote  byte // '"', '\'', 0 = 따옴표 없음
	Offset int
}

/*
내부 상태를 바꾸기에 *로 전달해야 함.
*/
func New(input string) *Tokenizer {
	buf := []byte(input)
	starts := []int{0}
	for i, c := range buf {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &Tokenizer{buf: buf, lineStarts: starts}
}

var rcdataTags = map[string]bool{"title": true, "textarea": true}

var rawTextTags = map[string]bool{
	"script": true, "style": true, "textarea": true, "title": true,
	"iframe": true, "noembed": true, "noframes": true, "xmp": true,
	"noscript": true, // 스크립트 켜진 브라우저 기준, 꺼져 있으면 일반 마크업
}

// Next() - Token 꺼냄.
func (t *Tokenizer) Next() Token {
	if len(t.buf) <= t.pos {
		return Token{Type: ErrToken}
	}

	if t.rawTag != "" {
		return t.readRawText()
	}

	if !t.isTagStart() {
		return t.readText()
	}

	switch t.buf[t.pos+1] {
	case '!':
		return t.readMarkupDeclaration()
	case '?':
		return t.readBogusComment(t.pos + 1) // '?' 도 주석 내용에 포함.
	case '/':
		return t.readEndTag()
	default:
		return t.readTag(StartTagToken)
	}
}

// readText() - '<' 찾기
func (t *Tokenizer) readText() Token {
	start := t.pos
	for t.pos < len(t.buf) {
		if t.isTagStart() {
			break
		}
		t.pos++
	}
	return Token{Type: TextToken, Data: string(t.buf[start:t.pos]), Offset: start}
}

// readTag() - '>' 찾기
func (t *Tokenizer) readTag(typ TokenType) Token {
	start := t.pos
	t.pos++ // skip '<'
	if typ == EndTagToken {
		t.pos++
	}

	nameStart := t.pos
	for t.pos < len(t.buf) && !isTagNameEnd(t.buf[t.pos]) {
		t.pos++
	}
	name := toASCIILower(t.buf[nameStart:t.pos])
	attrs, selfClosing := t.readAttributes()
	t.skipToTagEnd()

	if typ == StartTagToken && rawTextTags[name] {
		t.rawTag = name
	}
	return Token{Type: typ, Name: name, Attrs: attrs, Data: string(t.buf[start:t.pos]), Offset: start, SelfClosing: selfClosing}
}

// readRawRext() <script> 등의 내용을 닫는 태그 직전까지
func (t *Tokenizer) readRawText() Token {
	name := t.rawTag
	t.rawTag = ""

	var end int
	if name == "script" {
		end = t.scriptDataEnd(t.pos)
	} else {
		end = t.pos
		for end < len(t.buf) && !t.isEndTagAt(end, name) {
			end++
		}
	}

	if end == t.pos {
		return t.Next() // 내용이 비면 다음 태그 탐색
	}

	tok := Token{Type: TextToken, Data: string(t.buf[t.pos:end]), Offset: t.pos, Raw: !rcdataTags[name]}
	t.pos = end
	return tok
}

// Attr() 이름이 name인 첫 번째 속성 값 반환
func (tok Token) Attr(name string) (string, bool) {
	for _, a := range tok.Attrs {
		if a.Name == name {
			return a.Value, true
		}
	}
	return "", false
}

func (t *Tokenizer) readAttribute() Attribute {
	// 이름
	nameStart := t.pos
	for t.pos < len(t.buf) && !isAttrNameEnd(t.buf[t.pos]) {
		t.pos++
	}
	a := Attribute{Name: toASCIILower(t.buf[nameStart:t.pos]), Offset: nameStart}

	// '='가 없으면 값 없는 속성
	t.skipSpace()
	if len(t.buf) <= t.pos || t.buf[t.pos] != '=' {
		return a
	}
	t.pos++
	t.skipSpace()
	if len(t.buf) <= t.pos {
		return a
	}

	// 값
	switch q := t.buf[t.pos]; q {
	case '"', '\'':
		t.pos++
		valStart := t.pos
		for t.pos < len(t.buf) && t.buf[t.pos] != q {
			t.pos++
		}
		a.Quote = q
		a.Value = string(t.buf[valStart:t.pos])
		if t.pos < len(t.buf) {
			t.pos++
		}
	default:
		valStart := t.pos
		for t.pos < len(t.buf) && !isUnquotedValueEnd(t.buf[t.pos]) {
			t.pos++
		}
		a.Value = string(t.buf[valStart:t.pos])
	}
	return a
}

func (t *Tokenizer) readAttributes() ([]Attribute, bool) {
	var attrs []Attribute
	selfClosing := false
	for {
		t.skipSpace()
		if len(t.buf) <= t.pos {
			return attrs, selfClosing
		}
		c := t.buf[t.pos]
		if c == '>' {
			return attrs, selfClosing
		}
		if c == '/' {
			t.pos++
			selfClosing = t.pos < len(t.buf) && t.buf[t.pos] == '>'
			continue
		}
		attrs = append(attrs, t.readAttribute())
	}
}

func (tt TokenType) String() string {
	switch tt {
	case ErrToken:
		return "ERR"
	case TextToken:
		return "TEXT"
	case StartTagToken:
		return "START"
	case EndTagToken:
		return "END"
	case CommentToken:
		return "COMMENT"
	case DoctypeToken:
		return "DOCTYPE"
	}
	return "UNKNOWN"
}

func (t *Tokenizer) Position(offset int) (line, col int) {
	if offset < 0 {
		offset = 0
	}
	if len(t.buf) < offset {
		offset = len(t.buf)
	}
	i := sort.Search(len(t.lineStarts), func(k int) bool {
		return offset < t.lineStarts[k]
	}) - 1
	return i + 1, utf8.RuneCount(t.buf[t.lineStarts[i]:offset]) + 1
}

// readMarkupDeclaration(): "<!"다음을 보고 주석/DOCTYPE/가짜선언 구분
func (t *Tokenizer) readMarkupDeclaration() Token {
	rest := t.buf[t.pos+2:]
	switch {
	case 2 <= len(rest) && rest[0] == '-' && rest[1] == '-':
		return t.readComment()
	case hasPrefixFold(rest, "doctype"):
		return t.readDoctype()
	default:
		return t.readBogusComment(t.pos + 2)
	}
}

// readEndTag(): </ 뒤 판별
func (t *Tokenizer) readEndTag() Token {
	if len(t.buf) <= t.pos+2 { // "</"로 끝남 -> 텍스트
		start := t.pos
		t.pos = len(t.buf)
		return Token{Type: TextToken, Data: string(t.buf[start:]), Offset: start}
	}
	c := t.buf[t.pos+2]
	switch {
	case isASCIIAlpha(c):
		return t.readTag(EndTagToken)
	case c == '>':
		t.pos += 3 // </> 버림
		return t.Next()
	default:
		return t.readBogusComment(t.pos + 2)
	}
}

// readComment(): "<!--" 주석
func (t *Tokenizer) readComment() Token {
	start := t.pos
	i := t.pos + 4 // "<!--" 다음

	// <!--> <!--->는 즉시 닫히는 빈 주석
	if i < len(t.buf) && t.buf[i] == '>' {
		t.pos = i + 1
		return Token{Type: CommentToken, Offset: start}
	}
	if i+1 < len(t.buf) && t.buf[i] == '-' && t.buf[i+1] == '>' {
		t.pos = i + 2
		return Token{Type: CommentToken, Offset: start}
	}

	j := i
	for j = i; j < len(t.buf); j++ {
		if t.buf[j] != '-' {
			continue
		}
		if j+2 < len(t.buf) && t.buf[j+1] == '-' && t.buf[j+2] == '>' { // -->
			t.pos = j + 3
			return Token{Type: CommentToken, Data: string(t.buf[i:j]), Offset: start}
		}
		if j+3 < len(t.buf) && t.buf[j+1] == '-' && t.buf[j+2] == '!' && t.buf[j+3] == '>' { // --!>
			t.pos = j + 4
			return Token{Type: CommentToken, Data: string(t.buf[i:j]), Offset: start}
		}
	}

	// 닫히지 않고 끝까지 주석인 경우
	t.pos = len(t.buf)
	return Token{Type: CommentToken, Data: string(t.buf[i:j]), Offset: start}
}

// readBogusComment(): <!foo> <?xml?> </ b> 잘못된 주석
func (t *Tokenizer) readBogusComment(contentStart int) Token {
	start := t.pos
	i := contentStart
	for i < len(t.buf) && t.buf[i] != '>' {
		i++
	}
	data := string(t.buf[contentStart:i])
	if i < len(t.buf) {
		i++ // '>
	}
	t.pos = i
	return Token{Type: CommentToken, Data: data, Offset: start}
}

// readDoctype(): DOCTYPE
func (t *Tokenizer) readDoctype() Token {
	start := t.pos
	t.pos += 9 // "<!doctype"
	t.skipSpace()

	nameStart := t.pos
	for t.pos < len(t.buf) && !isTagNameEnd(t.buf[t.pos]) {
		t.pos++
	}
	name := toASCIILower(t.buf[nameStart:t.pos])
	t.skipToTagEnd()

	return Token{Type: DoctypeToken, Name: name, Data: string(t.buf[start:t.pos]), Offset: start}
}

// hasPrefixFold(: 대소문자 무시 접두사 비교
func hasPrefixFold(b []byte, prefix string) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := b[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}

// scriptDataEnd(): <script>의 내용이 실제로 끝나는지 위치 찾음.
func (t *Tokenizer) scriptDataEnd(from int) int {
	const (
		data = iota
		escaped
		doubleEscaped
	)
	state := data

	for i := from; i < len(t.buf); {
		switch {
		case t.isEndTagAt(i, "script"):
			if state == doubleEscaped {
				state = escaped // 닫지 않음.
				i += len("</script")
				continue
			}
			return i
		case state == data && t.hasAt(i, "<!--"):
			state = escaped
			i += 4
			continue
		case state == escaped && t.isStartTagAt(i, "script"):
			state = doubleEscaped
			i += len("<script")
			continue
		case state != data && t.hasAt(i, "-->"):
			state = data
			i += 3
			continue
		}
		i++
	}
	return len(t.buf)
}

func (t *Tokenizer) skipToTagEnd() {
	for t.pos < len(t.buf) && t.buf[t.pos] != '>' {
		t.pos++
	}
	if t.pos < len(t.buf) {
		t.pos++ // '>' 포함.
	}
}

func (t *Tokenizer) isTagStart() bool {
	if t.pos >= len(t.buf) || t.buf[t.pos] != '<' {
		return false
	}
	if t.pos+1 >= len(t.buf) {
		return false // '<' 로 끝남.
	}
	c := t.buf[t.pos+1]
	return isASCIIAlpha(c) || c == '/' || c == '!' || c == '?'
}

func (t *Tokenizer) isEndTagAt(i int, name string) bool {
	if t.buf[i] != '<' || len(t.buf) <= i+1 || t.buf[i+1] != '/' {
		return false
	}
	j := i + 2
	if len(t.buf) <= j+len(name) {
		return false
	}
	for k := 0; k < len(name); k++ {
		c := t.buf[j+k]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != name[k] {
			return false
		}
	}
	return isTagNameEnd(t.buf[j+len(name)])
}

// ASCII
func isASCIIAlpha(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

func toASCIILower(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

func isHTMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r'
}

func isTagNameEnd(c byte) bool {
	return isHTMLSpace(c) || c == '/' || c == '>'
}

func isAttrNameEnd(c byte) bool {
	return isHTMLSpace(c) || c == '/' || c == '>' || c == '='
}

func isUnquotedValueEnd(c byte) bool {
	return isHTMLSpace(c) || c == '>'
}

func (t *Tokenizer) skipSpace() {
	for t.pos < len(t.buf) && isHTMLSpace(t.buf[t.pos]) {
		t.pos++
	}
}

// hasAt(): buf[i] 부터가 s로 시작하는지 확인
func (t *Tokenizer) hasAt(i int, s string) bool {
	if len(t.buf) < i+len(s) {
		return false
	}
	for k := 0; k < len(s); k++ {
		if t.buf[i+k] != s[k] {
			return false
		}
	}
	return true
}

// isStartTagAt(): buf[i] 부터가 <name 인지 확인
func (t *Tokenizer) isStartTagAt(i int, name string) bool {
	if t.buf[i] != '<' {
		return false
	}
	j := i + 1
	if len(t.buf) <= j+len(name) {
		return false
	}
	for k := 0; k < len(name); k++ {
		c := t.buf[j+k]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != name[k] {
			return false
		}
	}
	return isTagNameEnd(t.buf[j+len(name)])
}
