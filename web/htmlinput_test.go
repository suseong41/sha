package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/suseong41/sha/fetcher"
)

// 표본 하나 — 로그인 폼이 남의 도메인으로 간다.
const sampleHTML = `<!DOCTYPE html><html><body>` +
	`<form action="https://collect.example.net/p" method="post">` +
	`<input type="text" name="uid"><input type="password" name="pw">` +
	`</form></body></html>`

// mustNotFetch(): 불리면 시험을 깨뜨린다 — html 을 받았으면 밖으로 나가지 않아야 함.
func mustNotFetch(t *testing.T) fetchFunc {
	t.Helper()
	return func(ctx context.Context, rawURL string) (*fetcher.Page, error) {
		t.Errorf("가져오기가 불렸다 (url=%q) — html 을 받으면 나가지 않아야 함", rawURL)
		return nil, errors.New("불리면 안 됨")
	}
}

// body(): scanRequest 를 요청 본문으로.
func body(t *testing.T, req scanRequest) string {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func has(res scanResponse, code string) bool {
	for _, f := range res.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// 받은 html 을 스캔한다 — 그리고 가져오러 나가지 않는다.
func TestScanAcceptsHTML(t *testing.T) {
	h := newHandler(mustNotFetch(t))
	rec := postScan(h, body(t, scanRequest{HTML: sampleHTML, URL: "https://mybank.example.com/login"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("상태 %d, want 200 — 본문 %s", rec.Code, rec.Body.String())
	}
	res := decode(t, rec)
	if !has(res, "cross-origin-password-form") {
		t.Errorf("발견 %v — cross-origin-password-form 이 있어야 함", res.Findings)
	}
	if res.URL != "https://mybank.example.com/login" {
		t.Errorf("url %q — 보낸 주소를 그대로 돌려줘야 함", res.URL)
	}
}

// url 없이 html 만 — 출처 규칙은 §3 대로 물러난다.
func TestScanHTMLWithoutURL(t *testing.T) {
	h := newHandler(mustNotFetch(t))
	rec := postScan(h, body(t, scanRequest{HTML: sampleHTML}))
	if rec.Code != http.StatusOK {
		t.Fatalf("상태 %d, want 200", rec.Code)
	}
	res := decode(t, rec)
	if has(res, "cross-origin-password-form") {
		t.Error("출처를 모르는데 교차 출처로 단정했다")
	}
	if res.URL != "" {
		t.Errorf("url %q — 준 적 없으면 비어야 함", res.URL)
	}
}

// 둘 다 없으면 400.
func TestScanNeedsInput(t *testing.T) {
	rec := postScan(newHandler(mustNotFetch(t)), `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("상태 %d, want 400", rec.Code)
	}
}

// 빈 문자열은 html 이 아니다 — url 이 있으면 여전히 가져온다.
func TestScanEmptyHTMLStillFetches(t *testing.T) {
	f := &fakeFetch{page: &fetcher.Page{URL: "https://a.example/", Body: []byte("<p>ok</p>")}}
	rec := postScan(newHandler(f.get), body(t, scanRequest{URL: "https://a.example/", HTML: ""}))
	if rec.Code != http.StatusOK {
		t.Fatalf("상태 %d, want 200", rec.Code)
	}
	if decode(t, rec).URL != "https://a.example/" {
		t.Error("가져오지 않았다")
	}
}

// 흘려보낼 때 가져오기 단계는 아예 없다 — 그리는 쪽이 이 계약을 본다.
func TestScanHTMLHasNoFetchStage(t *testing.T) {
	evs := postStream(t, newHandler(mustNotFetch(t)), body(t, scanRequest{HTML: sampleHTML}))
	var names []string
	for _, ev := range evs {
		if ev.T == "begin" {
			names = append(names, ev.Name)
		}
	}
	if len(names) != 1 || names[0] != "scan" {
		t.Errorf("단계 %v — scan 하나여야 함", names)
	}
	if evs[len(evs)-1].T != "done" {
		t.Errorf("마지막 줄이 %q, want done", evs[len(evs)-1].T)
	}
}

// 로그가 둘을 구별한다 — 받은 것을 가져온 것처럼 적으면 안 된다.
func TestScanLogsInputKind(t *testing.T) {
	h, buf := logged(mustNotFetch(t))
	postScan(h, body(t, scanRequest{HTML: sampleHTML, URL: "https://mybank.example.com/login"}))
	if got := records(t, buf)[0]["input"]; got != "html" {
		t.Errorf("input=%v, want html", got)
	}

	f := &fakeFetch{page: &fetcher.Page{URL: "https://a.example/", Body: []byte("<p>ok</p>")}}
	h2, buf2 := logged(f.get)
	postScan(h2, scanRequestFor("https://a.example/"))
	if got := records(t, buf2)[0]["input"]; got != "url" {
		t.Errorf("input=%v, want url", got)
	}
}

// html 도 본문 상한 안에 들어와야 한다.
func TestScanHTMLTooLarge(t *testing.T) {
	big := strings.Repeat("a", maxBodyBytes+1)
	rec := postScan(newHandler(mustNotFetch(t)), body(t, scanRequest{HTML: big}))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("상태 %d, want 413", rec.Code)
	}
}
