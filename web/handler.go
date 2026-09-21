package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/suseong41/sha/fetcher"
	"github.com/suseong41/sha/scanner"
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

type event struct {
	T      string        `json:"t"`
	Name   string        `json:"name,omitempty"`
	Text   string        `json:"text,omitempty"`
	URL    string        `json:"url,omitempty"`
	Final  string        `json:"final,omitempty"`
	MS     int64         `json:"ms,omitempty"`
	Result *scanResponse `json:"result,omitempty"`
}

type emitter struct {
	enc   *json.Encoder
	flush func()
}

func countTokens(res scanner.Result) int {
	n := 0
	for _, c := range res.Tokens {
		n += c
	}
	return n
}

func (e *emitter) send(ev event) {
	if e.enc == nil {
		return
	}
	e.enc.Encode(ev)
	e.flush()
}

// streamTo(): 스트리밍이면 헤더를 내보내고 emitter 생성
func streamTo(w http.ResponseWriter, r *http.Request) *emitter {
	f, ok := w.(http.Flusher)
	if !ok || !strings.Contains(r.Header.Get("Accept"), ndjson) {
		return &emitter{}
	}
	w.Header().Set("Content-Type", ndjson)
	w.Header().Set("X-Contetn-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	f.Flush()
	return &emitter{enc: json.NewEncoder(w), flush: f.Flush}
}

const ndjson = "application/x-ndjson"

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

// fetchFailure(): 닿은 뒤에 생긴 실패만 응답.
func fetchFailure(reason string) string {
	switch reason {
	case "timeout":
		return "10초 안에 응답이 없었습니다 — 서버가 느리거나, 사람이 아닌 요청을 막고 있을 수 있습니다."
	case "tls":
		return "인증서를 검증하지 못했습니다."
	case "too_large":
		return "페이지가 5MB 를 넘어 받지 않았습니다."
	}
	return "가져오지 못했습니다."
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

	out := streamTo(w, r)
	out.send(event{T: "start", URL: req.URL})

	out.send(event{T: "begin", Name: "fetch"})
	fetched := time.Now()
	page, err := h.fetch(r.Context(), req.URL)
	if err != nil {
		reason := failureReason(err)
		h.log.Warn("scan", "status", http.StatusBadGateway, "reason", reason,
			"scheme", scheme, "host", host, "ms", time.Since(start).Milliseconds())
		msg := fetchFailure(reason)
		if out.enc != nil {
			out.send(event{T: "error", Text: msg})
			return
		}
		writeJSON(w, http.StatusBadGateway, errorResponse{msg})
		return
	}
	out.send(event{T: "end", Name: "fetch", MS: time.Since(fetched).Milliseconds(), Text: fmt.Sprintf("%d 바이트", len(page.Body)), Final: page.URL})

	out.send(event{T: "begin", Name: "scan"})
	scanned := time.Now()
	res := scanner.ScanURL(string(page.Body), page.URL)
	scanner.SortBySeverity(res.Findings)
	scanMS := time.Since(scanned).Milliseconds()

	body := scanResponse{URL: page.URL, Findings: []findingJSON{}, Notes: []string{}}
	for _, f := range res.Findings {
		body.Findings = append(body.Findings, findingJSON{
			Line: f.Line, Col: f.Col,
			Severity: f.Severity.String(), Class: f.Class.String(),
			Code: f.Code, Title: f.Title, Evidence: f.Evidence,
		})
	}
	body.Notes = append(body.Notes, res.Notes...)
	out.send(event{T: "end", Name: "scan", MS: scanMS, Text: fmt.Sprintf("토큰 %d개 · 발견 %d건", countTokens(res), len(res.Findings))})

	_, finalHost := schemeHost(page.URL)
	h.log.Info("scan", "status", http.StatusOK, "scheme", scheme, "host", host, "final_host", finalHost,
		"findings", len(res.Findings), "notes", len(res.Notes), "bytes", len(page.Body),
		"ms", time.Since(start).Milliseconds())

	if out.enc != nil {
		out.send(event{T: "done", MS: time.Since(start).Milliseconds(), Result: &body})
		return
	}
	writeJSON(w, http.StatusOK, body)
}
