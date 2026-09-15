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
)

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
	resp, err := f.Get(context.Background(), srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("루프백 서버를 가져왔다")
	}
	if !strings.Contains(err.Error(), "루프백") {
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
	resp, err := f.Get(context.Background(), "http://innocent.example/x")
	if err != nil {
		t.Fatalf("가져오지 못함: %v", err)
	}
	resp.Body.Close()

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
