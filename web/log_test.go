package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/suseong41/suseong-html-analyzer/fetcher"
)

// logged(): 로그를 버퍼에 JSON 으로 받는 핸들러.
func logged(fetch fetchFunc) (http.Handler, *bytes.Buffer) {
	var buf bytes.Buffer
	return newLoggedHandler(fetch, slog.New(slog.NewJSONHandler(&buf, nil)), 0), &buf
}

// records(): 로그 한 줄 -> JOSN 객체 하나
func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("로그 한 줄이 JSON 이 아니다: %q", line)
		}
		out = append(out, m)
	}
	return out
}

const secretURL = "https://user:pw@example.com:8443/reset?token=SECRET#frag"

func TestScanLogKeepsOnlySchemeAndHost(t *testing.T) {
	ff := &fakeFetch{page: &fetcher.Page{URL: "https://www.example.com/reset?token=SECRET", Body: []byte("<p>hi</p>")}}
	h, buf := logged(ff.get)
	postScan(h, scanRequestFor(secretURL))

	recs := records(t, buf)
	if len(recs) != 1 {
		t.Fatalf("로그가 %d줄 — 요청 하나에 한 줄이어야 한다", len(recs))
	}
	r := recs[0]
	for k, want := range map[string]any{
		"status": 200.0, "scheme": "https", "host": "example.com:8443", "final_host": "www.example.com",
		"findings": 0.0, "notes": 0.0, "bytes": 9.0, // "<p>hi</p>" 는 9바이트
	} {
		if r[k] != want {
			t.Errorf("%s = %v — 원하는 값: %v", k, r[k], want)
		}
	}
	for _, leak := range []string{"SECRET", "pw", "user", "/reset", "frag"} {
		if strings.Contains(buf.String(), leak) {
			t.Errorf("로그에 %q 가 남았다: %s", leak, buf.String())
		}
	}
}

// 502 원인을 종류로 남김
func TestScanLogFailureReason(t *testing.T) {
	wrap := func(err error) error { return fmt.Errorf("Get %q: %w", secretURL, err) }
	cases := []struct {
		err  error
		want string
	}{
		{wrap(fetcher.ErrBlocked), "blocked"},
		{wrap(fetcher.ErrTooLarge), "too_large"},
		{wrap(&net.DNSError{Err: "no such host", Name: "x", IsNotFound: true}), "dns"},
		{wrap(&tls.CertificateVerificationError{Err: errors.New("unknown authority")}), "tls"},
		{wrap(context.DeadlineExceeded), "timeout"},
		{wrap(errors.New("connection refused")), "other"},
	}
	for _, c := range cases {
		h, buf := logged((&fakeFetch{err: c.err}).get)
		postScan(h, scanRequestFor(secretURL))
		r := records(t, buf)[0]
		if r["status"] != 502.0 || r["reason"] != c.want {
			t.Errorf("status=%v reason=%v — 원하는 값: 502 %s", r["status"], r["reason"], c.want)
		}
		if strings.Contains(buf.String(), "SECRET") {
			t.Errorf("%s: 오류 문자열이 로그에 들어갔다: %s", c.want, buf.String())
		}
	}
}

// 거절한 요청은 무엇을 보냈는지 남기지 않음.
func TestScanLogRejecteWithoutInput(t *testing.T) {
	h, buf := logged((&fakeFetch{}).get)
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(scanRequestFor(secretURL)))
	req.Header.Set("Content-Type", "text/plain")
	h.ServeHTTP(httptest.NewRecorder(), req)

	r := records(t, buf)[0]
	if r["status"] != 415.0 || r["reason"] != "content_type" {
		t.Errorf("status=%v reason=%v", r["status"], r["reason"])
	}
	if strings.Contains(buf.String(), "SECRET") || strings.Contains(buf.String(), "example.com") {
		t.Errorf("거절한 요청의 내용이 로그에 들어갔다: %s", buf.String())
	}
}
