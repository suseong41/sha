package report

import (
	"html/template"
	"io"

	"github.com/suseong41/suseong-html-analyzer/scanner"
)

// tplText: 템플릿 본문은 상수로 이스케이프 우회 막음
const tplText = `<!doctype html>
<html lang="ko">
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>스캔 결과</title>
<h1>스캔 결과</h1>
<p>대상: <code>{{.URL}}</code></p>
{{if .Result.Findings}}
<table>
<tr><th>위치</th><th>심각도</th><th>분류</th><th>코드</th><th>증거</th></tr>
{{range .Result.Findings}}<tr><td>{{.Line}}:{{.Col}}</td><td>{{.Severity}}</td><td>{{.Class}}</td><td>{{.Code}}</td><td><code>{{.Evidence}}</code></td></tr>
{{end}}</table>
{{else}}
<p>발견 없음</p>
{{end}}
{{if .Result.Notes}}
<h2>참고</h2>
<ul>{{range .Result.Notes}}<li>{{.}}</li>
{{end}}</ul>
{{end}}
`

var tpl = template.Must(template.New("report").Parse(tplText))

type page struct {
	URL    string
	Result scanner.Result
}

// WriteHTML(): 스캔 결과를 HTML 한 장으로 씀
func WriteHTML(w io.Writer, pageURL string, res scanner.Result) error {
	return tpl.Execute(w, page{pageURL, res})
}
