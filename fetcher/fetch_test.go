package fetcher

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// 203.0.113.7은 TEST-NET-3 IP 주소 범위
// https://www.rfc-editor.org/info/rfc5737/

// mustNodial: 거부돼야 하는 테스트
func mustNotDial(t *testing.T) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _, addr string) (net.Conn, error) {
		t.Errorf("%s로 접속을 시도했다.", addr)
		return nil, errors.New("나가면 안된다")
	}
}

func fixedLookup(ss ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(context.Context, string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, s := range ss {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

// 가짜 없이 진짜 서버로. httptest는 루프백에 뜸 - 거부돼야 함.
func TestGetRefusesLoopbackServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("요청이 서버에 도달했다. - 막혔어야 함.")
	}))
	defer srv.Close()

	f := Fetcher{dial: mustNotDial(t)}
	if _, err := f.Get(context.Background(), srv.URL); err == nil {
		t.Fatal("루프백 서버를 가져왔다")
	} else if !strings.Contains(err.Error(), "루프백") {
		t.Errorf("이유가 안 담겼다: %v", err)
	}
}

// 이름은 멀쩡하나 주소가 메타데이터인 경우
func TestGetRefusesMetadataBehindInnocentName(t *testing.T) {
	f := Fetcher{lookup: fixedLookup("169.254.169.254"), dial: mustNotDial(t)}
	_, err := f.Get(context.Background(), "http://cdn.example.com/logo.png")
	if err == nil {
		t.Fatal("메타데이터 주소로 나갔다")
	}
	for _, want := range []string{"169.254.169.254", "링크로컬"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("오류에 %q 가 없다: %v", want, err)
		}
	}
}

// 답이 여럿이고 하나만 내부면 전체를 거부
func TestGetRefusesWhenAnyAddressIsInternal(t *testing.T) {
	f := Fetcher{lookup: fixedLookup("93.184.216.34", "127.0.0.1"), dial: mustNotDial(t)}
	if _, err := f.Get(context.Background(), "http://mixed.example/"); err == nil {
		t.Fatal("일부가 루프백인데 통과시켰다")
	}
}

// 이름은 풀렸는데 답이 비어있을 때, 검사가 없으면 (nil, nil) 반환
func TestGetRefusesWhenLookupReturnsNothing(t *testing.T) {
	f := Fetcher{lookup: fixedLookup(), dial: mustNotDial(t)}
	_, err := f.Get(context.Background(), "http://empty.example/")
	if err == nil {
		t.Fatal("빈 응답인데 통과시킴")
	}
	if !strings.Contains(err.Error(), "주소를 찾지 못했다") {
		t.Errorf("우리 검사가 아니라 net/http 가 대신 막았다: %v", err)
	}
}

// 검증한 주소로 접속하고, 이름은 한 번만 푼다.
func TestDialUsesCheckedAddressAndResolvesOnce(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	lookups := 0
	var dialed []string
	f := Fetcher{
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			lookups++
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
		},
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			return net.Dial(network, strings.TrimPrefix(srv.URL, "http://"))
		},
	}
	if _, err := f.Get(context.Background(), "http://innocent.example/x"); err != nil {
		t.Fatalf("가져오지 못함: %v", err)
	}

	if len(dialed) != 1 || dialed[0] != "203.0.113.7:80" {
		t.Errorf("검증한 주소로 안 갔다: %v", dialed)
	}
	if lookups != 1 {
		t.Errorf("이름을 %d 번 풀었다", lookups)
	}
}

func TestGetRejectNonHTTPScheme(t *testing.T) {
	f := Fetcher{dial: mustNotDial(t)}
	for _, u := range []string{"file:///etc/passwd", "gopher://x/", "ftp://x/"} {
		_, err := f.Get(context.Background(), u)
		if err == nil {
			t.Errorf("%s 를 받아들였다", u)
			continue
		}
		if !strings.Contains(err.Error(), "http/https") {
			t.Errorf("%s: 우리 검사가 아니라 다른 데서 막혔다: %v", u, err)
		}
	}
}

// toSerever: lookup은 공인 IP를 주고, dial은 실제로 테스트 서버에 연결
func toServer(srv *httptest.Server) Fetcher {
	host := strings.TrimPrefix(srv.URL, "http://")
	return Fetcher{
		lookup: fixedLookup("203.0.113.7"),
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, host)
		},
	}
}

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestGetRejectsOversizedBody(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<p>ok</p><script>fetch('//evil')</script>"))
	})
	f := toServer(srv)
	f.MaxBytes = 20

	page, err := f.Get(context.Background(), "http://big.example/")
	if err == nil {
		t.Fatalf("상한을 넘겼는데 통과시킴: %q", page.Body)
	}
	if !strings.Contains(err.Error(), "상한") {
		t.Errorf("이유가 안 담겼다. %v", err)
	}
	if page != nil {
		t.Errorf("잘린 본문을 반환함: %q", page.Body)
	}
}

// 경계: 상한과 정확히 같은 크기는 통과해야 함.
func TestGetAcceptBodytAtExactLimit(t *testing.T) {
	body := strings.Repeat("a", 20)
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	})
	f := toServer(srv)
	f.MaxBytes = 20

	page, err := f.Get(context.Background(), "http://exact.example/")
	if err != nil {
		t.Fatalf("상한과 같은 크기를 막음: %v", err)
	}
	if string(page.Body) != body {
		t.Errorf("본문이 다름: %q", page.Body)
	}
}

func TestGetTimesOut(t *testing.T) {
	done := make(chan struct{})
	defer close(done)
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) { <-done })

	f := toServer(srv)
	f.Timeout = 50 * time.Millisecond

	start := time.Now()
	if _, err := f.Get(context.Background(), "http://slow.example/"); err == nil {
		t.Fatal("느린 서버를 기다려 성공")
	}
	if 2*time.Second < time.Since(start) {
		t.Errorf("상한이 안 먹었다: %v 걸림", time.Since(start))
	}
}

func TestGetStopsAfterMaxHops(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	})
	f := toServer(srv)
	f.MaxHops = 2

	_, err := f.Get(context.Background(), "http://loop.example/")
	if err == nil {
		t.Fatal("무한 리다이렉트를 따라감")
	}
	if !strings.Contains(err.Error(), "2 회") {
		t.Errorf("상한이 다른 곳에서 걸림: %v", err)
	}
}

// 출처 판정은 최종 URL로
func TestGetReportsFinalURL(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved" {
			w.Write([]byte("도착"))
			return
		}
		http.Redirect(w, r, "http://elsewhere.example/moved", http.StatusFound)
	})
	f := toServer(srv)

	page, err := f.Get(context.Background(), "http://start.example/")
	if err != nil {
		t.Fatalf("가져오지 못함: %v", err)
	}
	if page.URL != "http://elsewhere.example/moved" {
		t.Errorf("최종 URL이 아니라 %q를 돌려줬다", page.URL)
	}
}

// 주소가 여럿이면 첫 연결 실패 후 다음 주소를 시도
func TestDialTriesNextAddress(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	host := strings.TrimPrefix(srv.URL, "http://")

	const first, second = "203.0.113.7", "203.0.113.8"
	var tried []string
	f := Fetcher{
		lookup: fixedLookup(first, second),
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			tried = append(tried, addr)
			if addr == first+":80" {
				return nil, errors.New("연결 거부")
			}
			return net.Dial(network, host)
		},
	}
	if _, err := f.Get(context.Background(), "http://two.example/"); err != nil {
		t.Fatalf("두 번째 주소로 넘어가지 못했다: %v", err)
	}
	want := []string{first + ":80", second + ":80"}
	if len(tried) != 2 || tried[0] != want[0] || tried[1] != want[1] {
		t.Errorf("시도 순서가 %v — 원하는 값: %v", tried, want)
	}
}

func TestGetRejectRedirectToNonHTTPSchme(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	})
	f := toServer(srv)

	_, err := f.Get(context.Background(), "http://bait.example/")
	if err == nil {
		t.Fatal("file://로 바뀐 리다이렉트를 따라감")
	}
	if !strings.Contains(err.Error(), "http/https") {
		t.Errorf("우리가 막은 게 아님: %v", err)
	}
}
