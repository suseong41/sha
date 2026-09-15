package web

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"

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

type fetchFunc func(ctx context.Context, rawURL string) (*fetcher.Page, error)

type handler struct{ fetch fetchFunc }

// New(): 진짜 수집기를 쓰는 핸들러.
func New(f *fetcher.Fetcher) http.Handler { return newHandler(f.Get) }

func newHandler(fetch fetchFunc) http.Handler {
	h := &handler{fetch: fetch}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/scan", h.scan)
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

func (h *handler) scan(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, errorResponse{"Content-Type 은 application/json 이어야 함"})
		return
	}

	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		status := http.StatusBadRequest
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			status = http.StatusRequestEntityTooLarge
		}
		writeJSON(w, status, errorResponse{http.StatusText(status)})
		return
	}
	if req.URL == "" || maxURLLen < len(req.URL) {
		writeJSON(w, http.StatusBadRequest, errorResponse{"url 은 1~2048자"})
		return
	}

	page, err := h.fetch(r.Context(), req.URL)
	if err != nil {
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
	writeJSON(w, http.StatusOK, out)
}
