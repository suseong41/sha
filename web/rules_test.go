package web

import (
	"strings"
	"testing"

	"github.com/suseong41/sha/fetcher"
)

// 나온 규칙의 설명이 응답에 함께 온다.
func TestScanResponseCarriesExplanations(t *testing.T) {
	rec := postScan(newHandler(mustNotFetch(t)), body(t, scanRequest{HTML: sampleHTML, URL: "https://mybank.example.com/login"}))
	res := decode(t, rec)

	e, ok := res.Rules["cross-origin-password-form"]
	if !ok {
		t.Fatalf("설명이 안 실렸다 — rules %v", res.Rules)
	}
	if strings.TrimSpace(e.Why) == "" || strings.TrimSpace(e.Fix) == "" {
		t.Errorf("설명이 비었다: %+v", e)
	}
}

// 나온 코드만 싣는다 — 25종을 다 보내면 응답이 헛되이 커진다.
func TestScanResponseRulesOnlyForFound(t *testing.T) {
	rec := postScan(newHandler(mustNotFetch(t)), body(t, scanRequest{HTML: sampleHTML, URL: "https://mybank.example.com/login"}))
	res := decode(t, rec)

	found := map[string]bool{}
	for _, f := range res.Findings {
		found[f.Code] = true
	}
	for code := range res.Rules {
		if !found[code] {
			t.Errorf("%s: 나오지도 않은 규칙의 설명이 실렸다", code)
		}
	}
	if len(res.Rules) != len(found) {
		t.Errorf("설명 %d개 · 나온 코드 %d종 — 같아야 함", len(res.Rules), len(found))
	}
}

// 발견이 없어도 null 이 아니라 {} 다 — 받는 쪽이 Object.keys 에서 터진다.
func TestScanResponseRulesNeverNull(t *testing.T) {
	f := &fakeFetch{page: &fetcher.Page{URL: "https://a.example/", Body: []byte("<p>ok</p>")}}
	rec := postScan(newHandler(f.get), scanRequestFor("https://a.example/"))
	if got := rec.Body.String(); !strings.Contains(got, `"rules":{}`) {
		t.Errorf("빈 결과의 rules 가 {} 가 아니다: %s", got)
	}
}
