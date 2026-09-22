package web

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/suseong41/sha/fetcher"
)

// postNDJSON(): 흘려보내 달라고 청하고, 줄들을 받아 온다.
func postNDJSON(t *testing.T, h http.Handler, target string) []event {
	t.Helper()
	return postStream(t, h, scanRequestFor(target))
}

// postStream(): 본문을 그대로 보내 NDJSON 줄을 받는다 (html 입력용).
func postStream(t *testing.T, h http.Handler, body string) []event {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", ndjson)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != ndjson {
		t.Fatalf("Content-Type = %q, want %q", ct, ndjson)
	}
	var out []event
	for _, line := range strings.Split(strings.TrimSpace(rec.Body.String()), "\n") {
		if line == "" {
			continue
		}
		var ev event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("줄이 JSON 이 아니다: %q", line)
		}
		out = append(out, ev)
	}
	return out
}

func kinds(evs []event) string {
	var b []string
	for _, e := range evs {
		if e.Name != "" {
			b = append(b, e.T+":"+e.Name)
			continue
		}
		b = append(b, e.T)
	}
	return strings.Join(b, " ")
}

// 단계가 순서대로 온다 — 시작 · 가져오기 · 파싱 · 완료.
func TestStreamOrder(t *testing.T) {
	ff := &fakeFetch{page: &fetcher.Page{URL: "https://a.example/", Body: []byte("<p onclick=x>안녕</p>")}}
	evs := postNDJSON(t, newHandler(ff.get), "https://a.example/")

	want := "start begin:fetch end:fetch begin:scan end:scan done"
	if got := kinds(evs); got != want {
		t.Errorf("순서 %q\nwant  %q", got, want)
	}
}

// 마지막 done 의 result 는 스트리밍이 아닐 때의 응답과 **같아야** 한다.
func TestStreamResultMatchesPlain(t *testing.T) {
	page := &fetcher.Page{URL: "https://a.example/",
		Body: []byte(`<p onclick="x()">안녕</p><a href="javascript:1" target="_blank">z</a>`)}

	evs := postNDJSON(t, newHandler((&fakeFetch{page: page}).get), "https://a.example/")
	last := evs[len(evs)-1]
	if last.T != "done" || last.Result == nil {
		t.Fatalf("마지막 줄이 done 이 아니다: %+v", last)
	}
	streamed, _ := json.Marshal(last.Result)

	rec := postScan(newHandler((&fakeFetch{page: page}).get), scanRequestFor("https://a.example/"))
	plain := strings.TrimSpace(rec.Body.String())

	if string(streamed) != plain {
		t.Errorf("스트리밍 결과와 평소 응답이 다르다\n흘림: %s\n평소: %s", streamed, plain)
	}
}

// Accept 가 없으면 지금까지처럼 한 덩어리 JSON 이다.
func TestPlainUnchanged(t *testing.T) {
	ff := &fakeFetch{page: &fetcher.Page{URL: "https://a.example/", Body: []byte("<p>안녕</p>")}}
	rec := postScan(newHandler(ff.get), scanRequestFor("https://a.example/"))

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}
	if n := strings.Count(strings.TrimSpace(rec.Body.String()), "\n"); n != 0 {
		t.Errorf("한 줄이어야 하는데 줄바꿈이 %d개", n)
	}
}

// 가져오기가 실패하면 — 헤더는 이미 나갔으므로 상태 대신 error 줄로 알린다.
func TestStreamFetchError(t *testing.T) {
	ff := &fakeFetch{err: context.DeadlineExceeded}
	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(scanRequestFor("https://a.example/")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", ndjson)
	rec := httptest.NewRecorder()
	newHandler(ff.get).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("상태 %d, want 200 — 흘리기 시작한 뒤에는 상태를 바꿀 수 없다", rec.Code)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	var last event
	json.Unmarshal([]byte(lines[len(lines)-1]), &last)
	if last.T != "error" || last.Text == "" {
		t.Errorf("마지막 줄 %q — {\"t\":\"error\"} 여야 함", lines[len(lines)-1])
	}
	if strings.Contains(rec.Body.String(), `"t":"done"`) {
		t.Error("실패했는데 done 을 보냈다")
	}
}

// 흘려보내는 것이 진짜인지 — 가져오기가 끝나기 전에 앞줄이 도착해야 한다.
func TestStreamArrivesEarly(t *testing.T) {
	hold := make(chan struct{})
	fetch := func(ctx context.Context, rawURL string) (*fetcher.Page, error) {
		<-hold // 놓아줄 때까지 가져오기가 끝나지 않는다
		return &fetcher.Page{URL: rawURL, Body: []byte("<p>안녕</p>")}, nil
	}
	srv := httptest.NewServer(newHandler(fetch))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/scan", strings.NewReader(scanRequestFor("https://a.example/")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", ndjson)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	sc := bufio.NewScanner(resp.Body)
	early := make(chan string, 2)
	go func() {
		for i := 0; i < 2 && sc.Scan(); i++ {
			early <- sc.Text()
		}
	}()

	for i := 0; i < 2; i++ { // start · begin:fetch
		select {
		case line := <-early:
			if !strings.Contains(line, `"t":"start"`) && !strings.Contains(line, `"t":"begin"`) {
				t.Errorf("먼저 온 줄이 %q", line)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("가져오기가 끝나기 전에는 아무 줄도 오지 않았다 — 버퍼에 쌓고 있다")
		}
	}
	close(hold)
}

// 자리가 없어 거절할 때는 흘리기 전이므로 상태 코드로 말한다.
func TestStreamBusyStillUsesStatus(t *testing.T) {
	shortWait(t, 20*time.Millisecond)
	hf := newHold()
	h, _ := loggedMax(hf.get, 1)

	go postScan(h, scanRequestFor("https://first.example/"))
	waitEntered(t, hf, 1)

	req := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(scanRequestFor("https://second.example/")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", ndjson)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("상태 %d, want 503", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q — 거절은 평소 JSON 으로", ct)
	}
	close(hf.release)
}

// 단계 시간의 합이 전체를 넘지 않는다 — 단위를 잘못 쓰면 여기서 걸린다.
func TestStageTimesAddUp(t *testing.T) {
	ff := &fakeFetch{page: &fetcher.Page{URL: "https://a.example/", Body: []byte("<p onclick=x>안녕</p>")}}
	evs := postNDJSON(t, newHandler(ff.get), "https://a.example/")

	var sum int64
	var total int64
	for _, e := range evs {
		if e.T == "end" {
			sum += e.MS
		}
		if e.T == "done" {
			total = e.MS
		}
	}
	if sum > total {
		t.Errorf("단계 합 %dms 가 전체 %dms 보다 크다 — 단위가 섞였나(마이크로초?)", sum, total)
	}
}
