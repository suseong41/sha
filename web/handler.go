package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/suseong41/suseong-html-analyzer/fetcher"
	"github.com/suseong41/suseong-html-analyzer/scanner"
)

const (
	maxBodyBytes = 4 << 10 // 4KB
	maxURLLen    = 2048
)

// csp: API 응답을 누가 브라우저로 직접 열어도 실행되지 않게
// 페이지 헤더는 nginx가
const csp = "default-src 'none'; frame-ancestors 'none'"

// DefaultMaxScans: 동시에 처리할 스캔 수.
const DefaultMaxScans = 4

var maxWait = 2 * time.Second

type fetchFunc func(ctx context.Context, rawURL string) (*fetcher.Page, error)

type handler struct {
	fetch fetchFunc
	log   *slog.Logger
	slots chan struct{}
}

// New(): 진짜 수집기를 쓰는 핸들러. max는 동시에 처리할 스캔 수
func New(f *fetcher.Fetcher, log *slog.Logger, max int) http.Handler {
	return newLoggedHandler(f.Get, log, max)
}

// newHandler(): 로그를 버리는 핸들러.
func newHandler(fetch fetchFunc) http.Handler {
	return newLoggedHandler(fetch, slog.New(slog.DiscardHandler), 0)
}

// health(): 살아 있는지만 응답
func health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func newLoggedHandler(fetch fetchFunc, log *slog.Logger, max int) http.Handler {
	if max <= 0 {
		max = DefaultMaxScans
	}
	h := &handler{fetch: fetch, log: log, slots: make(chan struct{}, max)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/scan", h.scan)
	mux.HandleFunc("GET /healthz", health)
	return secureHeaders(mux)
}

// secureHeaders(): 모든 응답에 붙임.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

type scanRequest struct {
	URL string `json:"url"`
}

// findingJSON: Severity·Class를 이름으로 바꿔 보냄.
type findingJSON struct {
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	Severity string `json:"severity"`
	Class    string `json:"class"`
	Code     string `json:"code"`
	Title    string `json:"title"`
	Evidence string `json:"evidence"`
}

type scanResponse struct {
	URL      string        `json:"url"`
	Findings []findingJSON `json:"findings"`
	Notes    []string      `json:"notes"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// 넘기는 것: 결과(상태, 종류, 건수, 시간)와 대상의 scheme, host
// 넘기지 않는 것: 경로, 쿼리, 조각, userinfo, 요청, 본문, 오류 문자열

// schemeHost(): URL 에서 로그에 남겨도 되는 부분만.
func schemeHost(raw string) (scheme, host string) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", ""
	}
	return u.Scheme, u.Host
}

// failureReason(): 가져오기 실패를 종류별로 분리
func failureReason(err error) string {
	var dnsErr *net.DNSError
	var certErr *tls.CertificateVerificationError
	var netErr net.Error
	switch {
	case errors.Is(err, fetcher.ErrBlocked):
		return "blocked"
	case errors.Is(err, fetcher.ErrTooLarge):
		return "too_large"
	case errors.As(err, &dnsErr):
		return "dns"
	case errors.As(err, &certErr):
		return "tls"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	}
	return "other"
}

func (h *handler) reject(w http.ResponseWriter, status int, reason, msg string) {
	h.log.Info("scan rejected", "status", status, "reason", reason)
	writeJSON(w, status, errorResponse{msg})
}

func (h *handler) scan(w http.ResponseWriter, r *http.Request) {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		wait := time.NewTimer(maxWait)
		defer wait.Stop()
		select {
		case h.slots <- struct{}{}:
			defer func() { <-h.slots }()
		case <-r.Context().Done():
			return
		case <-wait.C:
			w.Header().Set("Retry-After", "1")
			h.reject(w, http.StatusServiceUnavailable, "busy", "지금은 처리 중인 요청이 많습니다")
			return
		}
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		h.reject(w, http.StatusUnsupportedMediaType, "content_type", "Content-Type 은 application/json 이어야 함")
		return
	}

	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		status := http.StatusBadRequest
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			status = http.StatusRequestEntityTooLarge
		}
		h.reject(w, status, "body", http.StatusText(status))
		return
	}
	if req.URL == "" || maxURLLen < len(req.URL) {
		h.reject(w, http.StatusBadRequest, "url_length", "url 은 1~2048자")
		return
	}

	start := time.Now()
	scheme, host := schemeHost(req.URL)
	page, err := h.fetch(r.Context(), req.URL)
	if err != nil {
		h.log.Warn("scan", "status", http.StatusBadGateway, "reason", failureReason(err),
			"scheme", scheme, "host", host, "ms", time.Since(start).Milliseconds())
		writeJSON(w, http.StatusBadGateway, errorResponse{"가져오지 못함"})
		return
	}

	res := scanner.ScanURL(string(page.Body), page.URL)
	scanner.SortBySeverity(res.Findings)

	out := scanResponse{URL: page.URL, Findings: []findingJSON{}, Notes: []string{}}
	for _, f := range res.Findings {
		out.Findings = append(out.Findings, findingJSON{
			Line: f.Line, Col: f.Col,
			Severity: f.Severity.String(), Class: f.Class.String(),
			Code: f.Code, Title: f.Title, Evidence: f.Evidence,
		})
	}
	out.Notes = append(out.Notes, res.Notes...)
	_, finalHost := schemeHost(page.URL)
	h.log.Info("scan", "status", http.StatusOK, "scheme", scheme, "host", host, "final_host", finalHost,
		"findings", len(res.Findings), "notes", len(res.Notes), "bytes", len(page.Body),
		"ms", time.Since(start).Milliseconds())
	writeJSON(w, http.StatusOK, out)
}
