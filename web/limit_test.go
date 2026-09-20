package web

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/suseong41/suseong-html-analyzer/fetcher"
)

// holdFetch: 슬롯을 잡은 채로 놓아줄 때까지 기다리는 가짜 수집기.
type holdFetch struct {
	entered chan struct{} // 수집기에 들어왔음을 알림
	release chan struct{} // 닫으면 전부 풀려난다
}

func newHold() *holdFetch {
	return &holdFetch{entered: make(chan struct{}, 64), release: make(chan struct{})}
}

func (f *holdFetch) get(ctx context.Context, rawURL string) (*fetcher.Page, error) {
	f.entered <- struct{}{}
	<-f.release
	return &fetcher.Page{URL: rawURL, Body: []byte("<p>안녕</p>")}, nil
}

// shortWait(): 기다리는 시간을 짧게 바꿔 두고, 끝나면 되돌림.
func shortWait(t *testing.T, d time.Duration) {
	t.Helper()
	old := maxWait
	maxWait = d
	t.Cleanup(func() { maxWait = old })
}

// loggedMax(): 상한을 정해 만든 핸들러와 로그 버퍼.
func loggedMax(fetch fetchFunc, max int) (http.Handler, *bytes.Buffer) {
	var buf bytes.Buffer
	return newLoggedHandler(fetch, slog.New(slog.NewJSONHandler(&buf, nil)), max), &buf
}

// waitEntered(): 수집기에 n 개가 들어올 때까지 기다림.
func waitEntered(t *testing.T, hf *holdFetch, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-hf.entered:
		case <-time.After(3 * time.Second):
			t.Fatalf("%d 번째 요청이 수집기까지 오지 않았다", i+1)
		}
	}
}

// 기다려도 자리가 안 나면 503 — 폭주는 거절한다.
func TestScanRejectsWhenBusy(t *testing.T) {
	shortWait(t, 20*time.Millisecond)
	hf := newHold()
	h, buf := loggedMax(hf.get, 1)

	go postScan(h, scanRequestFor("https://first.example/")) // 양성 — 하나뿐인 자리를 차지
	waitEntered(t, hf, 1)

	rec := postScan(h, scanRequestFor("https://second.example/")) // 음성 — 자리 없음
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("상태 %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q, want 1", got) // 언제 다시 오라고 말해 준다
	}

	var busy bool
	for _, r := range records(t, buf) {
		if r["reason"] == "busy" {
			busy = true
		}
	}
	if !busy {
		t.Errorf("거절을 로그에 남기지 않았다 — 상한을 올릴 때가 됐는지 운영자가 알 수 없다:\n%s", buf)
	}
	close(hf.release)
}

// 끝난 요청은 자리를 돌려준다.
func TestScanSlotReturned(t *testing.T) {
	hf := newHold()
	h, _ := loggedMax(hf.get, 1)

	done := make(chan int, 1)
	go func() { done <- postScan(h, scanRequestFor("https://first.example/")).Code }()
	waitEntered(t, hf, 1)
	close(hf.release) // 첫 요청을 풀어 준다

	if code := <-done; code != http.StatusOK {
		t.Fatalf("첫 요청 상태 %d, want 200", code)
	}
	if rec := postScan(h, scanRequestFor("https://third.example/")); rec.Code != http.StatusOK {
		t.Errorf("자리가 돌아오지 않았다 — 상태 %d, want 200", rec.Code) // defer 로 반납
	}
}

// 상한을 안 주면 DefaultMaxScans 만큼 — 그만큼은 받고 그다음이 503.
func TestScanDefaultLimit(t *testing.T) {
	shortWait(t, 20*time.Millisecond)
	hf := newHold()
	h, _ := loggedMax(hf.get, 0) // 0 -> 기본값
	for i := 0; i < DefaultMaxScans; i++ {
		go postScan(h, scanRequestFor("https://busy.example/"))
	}
	waitEntered(t, hf, DefaultMaxScans)

	if rec := postScan(h, scanRequestFor("https://one-more.example/")); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("기본 상한 %d 를 넘겼는데 상태 %d, want 503", DefaultMaxScans, rec.Code)
	}
	close(hf.release)
}

// 상태 확인은 상한과 무관하다 — 바빠서 죽어 가는 중에도 답해야 한다.
func TestHealthzIgnoresLimit(t *testing.T) {
	shortWait(t, 20*time.Millisecond)
	hf := newHold()
	h, _ := loggedMax(hf.get, 1)

	go postScan(h, scanRequestFor("https://first.example/"))
	waitEntered(t, hf, 1)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("스캔이 자리를 다 차지했을 때 /healthz 가 %d — 프로브가 죽으면 다시 띄워진다", rec.Code)
	}
	close(hf.release)
}

// 기본 상한은 부하 측정에서 나온 값이다 — 바꾸려면 다시 재야 한다.
// 5MB 페이지로 재니 256MB 제한에서 동시 9 까지 살고 10 부터 컨테이너가 죽었다(§12.49).
func TestDefaultMaxScansIsMeasured(t *testing.T) {
	if DefaultMaxScans != 4 {
		t.Errorf("DefaultMaxScans = %d, want 4 — 측정 없이 바꾸지 않는다", DefaultMaxScans)
	}
}

// 붐비는 것과 폭주는 다르다 — 기다리는 동안 자리가 나면 처리한다.
func TestScanWaitsForSlot(t *testing.T) {
	shortWait(t, 2*time.Second)
	hf := newHold()
	h, _ := loggedMax(hf.get, 1)

	first := make(chan int, 1)
	go func() { first <- postScan(h, scanRequestFor("https://first.example/")).Code }()
	waitEntered(t, hf, 1)

	second := make(chan int, 1)
	go func() { second <- postScan(h, scanRequestFor("https://second.example/")).Code }() // 자리 없음 — 기다린다

	time.Sleep(50 * time.Millisecond) // 둘째가 줄을 설 시간
	close(hf.release)                 // 첫째를 놓아준다 -> 자리가 난다

	if code := <-first; code != http.StatusOK {
		t.Errorf("첫 요청 %d, want 200", code)
	}
	select {
	case code := <-second:
		if code != http.StatusOK {
			t.Errorf("기다렸다 처리되어야 하는데 %d — 즉시 거절로 돌아갔나", code)
		}
	case <-time.After(5 * time.Second):
		t.Error("둘째 요청이 끝나지 않았다")
	}
}

// 클라이언트가 가 버리면 조용히 끝낸다 — 끊긴 연결에 503 을 쓰지 않는다.
func TestScanClientGone(t *testing.T) {
	shortWait(t, 5*time.Second) // 시간 초과가 아니라 취소로 끝나야 함
	hf := newHold()
	h, buf := loggedMax(hf.get, 1)

	go postScan(h, scanRequestFor("https://first.example/"))
	waitEntered(t, hf, 1)

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/api/scan",
		strings.NewReader(scanRequestFor("https://gone.example/"))).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() { h.ServeHTTP(rec, req); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel() // 클라이언트가 끊음

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("취소됐는데 핸들러가 끝나지 않았다")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("끊긴 연결에 본문을 썼다: %q", rec.Body.String())
	}
	if strings.Contains(buf.String(), "busy") { // 비어 있는 게 정답이다
		t.Errorf("클라이언트가 간 것을 폭주로 기록했다: %s", buf)
	}
	close(hf.release)
}
