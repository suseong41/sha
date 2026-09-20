package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hit(): 경로를 메서드로 두드려 봄.
func hit(h http.Handler, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// 살아 있으면 200 과 {"status":"ok"} — 그 이상은 말하지 않는다.
func TestHealthz(t *testing.T) {
	ff := &fakeFetch{}
	h, buf := logged(ff.get)
	rec := hit(h, http.MethodGet, "/healthz")

	if rec.Code != http.StatusOK {
		t.Errorf("상태 %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("본문이 JSON 이 아니다: %q", rec.Body.String())
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want ok", body["status"])
	}
	if len(body) != 1 {
		t.Errorf("본문에 status 말고 다른 것이 있다: %v", body) // 버전은 넣지 않는다
	}
	if ff.called {
		t.Error("상태 확인이 밖으로 나갔다 — 수집기를 불렀다")
	}
	if buf.Len() != 0 {
		t.Errorf("로그를 남겼다: %s", buf.String()) // 프로브가 초당 한 번씩 두드린다
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("보안 헤더가 안 붙었다") // 상태 확인도 같은 문을 지난다
	}
}

// GET 만 받는다 — HEAD 는 GET 에 딸려 오고, 나머지는 405.
func TestHealthzMethods(t *testing.T) {
	h := newHandler((&fakeFetch{}).get)
	cases := []struct {
		method string
		want   int
	}{
		{http.MethodGet, http.StatusOK},                  // 양성
		{http.MethodHead, http.StatusOK},                 // 양성 — GET 패턴이 HEAD 도 받는다
		{http.MethodPost, http.StatusMethodNotAllowed},   // 음성
		{http.MethodPut, http.StatusMethodNotAllowed},    // 음성
		{http.MethodDelete, http.StatusMethodNotAllowed}, // 음성
	}
	for _, c := range cases {
		if rec := hit(h, c.method, "/healthz"); rec.Code != c.want {
			t.Errorf("%s /healthz -> %d, want %d", c.method, rec.Code, c.want)
		}
	}
}
