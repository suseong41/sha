package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/suseong41/sha/fetcher"
)

// 닿은 뒤에 생긴 실패만 말해 준다. 닿기 전의 실패는 뭉뚱그린다 —
// 이름 해석 실패와 차단된 주소를 구별해 주면 내부 이름이 실재하는지 알려 주게 된다.
func TestFetchFailureMessage(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string // 본문에 들어 있어야 할 말
	}{
		{"시간 초과", context.DeadlineExceeded, "응답이 없"},                                     // 양성 — 공인 주소에 닿은 뒤
		{"인증서 검증 실패", &tls.CertificateVerificationError{}, "인증서"},                        // 양성
		{"5MB 초과", fetcher.ErrTooLarge, "5MB"},                                           // 양성
		{"차단된 주소", fetcher.ErrBlocked, "가져오지 못했습니다"},                                     // 음성 — 닿기 전
		{"이름 해석 실패", &net.DNSError{Err: "no such host", IsNotFound: true}, "가져오지 못했습니다"}, // 음성 — 닿기 전
		{"그 밖", errors.New("무언가"), "가져오지 못했습니다"},                                         // 음성
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := postScan(newHandler((&fakeFetch{err: c.err}).get), scanRequestFor("https://a.example/"))
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("상태 %d, want 502", rec.Code)
			}
			var out errorResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("본문이 JSON 이 아니다: %s", rec.Body.String())
			}
			if !strings.Contains(out.Error, c.want) {
				t.Errorf("본문 %q — %q 가 들어 있어야 함", out.Error, c.want)
			}
		})
	}
}

// 닿기 전의 실패 셋은 서로 구별되지 않아야 한다.
func TestFetchFailureHidesCause(t *testing.T) {
	var seen []string
	for _, err := range []error{
		fetcher.ErrBlocked,
		&net.DNSError{Err: "no such host", IsNotFound: true},
		errors.New("무언가"),
	} {
		rec := postScan(newHandler((&fakeFetch{err: err}).get), scanRequestFor("https://a.example/"))
		var out errorResponse
		json.Unmarshal(rec.Body.Bytes(), &out)
		seen = append(seen, out.Error)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] != seen[0] {
			t.Errorf("원인이 드러난다: %q vs %q", seen[0], seen[i])
		}
	}
}

// 흘려받을 때도 같은 말이 error 줄로 온다.
func TestStreamFailureMessage(t *testing.T) {
	evs := postNDJSON(t, newHandler((&fakeFetch{err: context.DeadlineExceeded}).get), "https://a.example/")
	last := evs[len(evs)-1]
	if last.T != "error" {
		t.Fatalf("마지막 줄이 %q", last.T)
	}
	if !strings.Contains(last.Text, "응답이 없") {
		t.Errorf("error 줄 %q — 시간 초과를 말해야 함", last.Text)
	}
}
