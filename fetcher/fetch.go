package fetcher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

// 오류 종류
var (
	ErrBlocked  = errors.New("내부·예약 주소")
	ErrTooLarge = errors.New("응답이 상한을 넘음")
)

// Fetcher: SSRF를 막는 HTTP 수집기
type Fetcher struct {
	// 상한. 0이면 기본값
	Timeout  time.Duration
	MaxBytes int64
	MaxHops  int

	// 테스트용. nil 이면 진짜 네트워크 씀
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (f *Fetcher) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if f.lookup != nil {
		return f.lookup(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (f *Fetcher) connect(ctx context.Context, network, addr string) (net.Conn, error) {
	if f.dial != nil {
		return f.dial(ctx, network, addr)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// dialChecked(): 이름을 한 번 풀고, 검증하고, 접속
func (f *Fetcher) dialChecked(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := f.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {

		return nil, fmt.Errorf("%s: 주소를 찾지 못했다", host)
	}

	// 하나라도 내부면 그 이름 자체를 거부
	for _, ip := range ips {
		if why := blockedReason(ip); why != "" {
			return nil, fmt.Errorf("%s(%s) 로는 접속하지 않는다: %s: %w", host, ip, why, ErrBlocked)
		}
	}
	var firstErr error
	for _, ip := range ips {
		conn, err := f.connect(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}

const (
	defaultTimeout  = 10 * time.Second
	defaultMaxBytes = 5 << 20 // 5MB
	defaultMaxHops  = 3
)

func (f *Fetcher) timeout() time.Duration {
	if 0 < f.Timeout {
		return f.Timeout
	}
	return defaultTimeout
}

func (f *Fetcher) maxBytes() int64 {
	if 0 < f.MaxBytes {
		return f.MaxBytes
	}
	return defaultMaxBytes
}

func (f *Fetcher) maxHops() int {
	if 0 < f.MaxHops {
		return f.MaxHops
	}
	return defaultMaxHops
}

// Page: 가져온 문서. URL은 최종 주소
type Page struct {
	URL  string
	Body []byte
}

func checkScheme(u *url.URL) error {
	if s := u.Scheme; s != "http" && s != "https" {
		return fmt.Errorf("%q: http/https 만 가져온다", s)
	}
	return nil
}

// checkRedirect(): hop마다 호출. 횟수와 scheme 확인
func (f *Fetcher) checkRedirect(req *http.Request, via []*http.Request) error {
	if f.maxHops() <= len(via) {
		return fmt.Errorf("리다이렉트가 %d 회를 넘는다", f.maxHops())
	}
	return checkScheme(req.URL)
}

// readLimited(): 상한까지 읽되, 넘치면 알림
func readLimited(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if max < int64(len(body)) {
		return nil, fmt.Errorf("%w: %d 바이트", ErrTooLarge, max)
	}
	return body, nil
}

// Get(): rawURL을 가져온다. (http(s)만 받음)
func (f *Fetcher) Get(ctx context.Context, rawURL string) (*Page, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if err := checkScheme(req.URL); err != nil {
		return nil, err
	}
	// 스캔마다 새 Transport를 사용 (재사용 금지)
	c := &http.Client{
		Transport:     &http.Transport{DialContext: f.dialChecked},
		CheckRedirect: f.checkRedirect,
		Timeout:       f.timeout(),
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, f.maxBytes())
	if err != nil {
		return nil, err
	}
	// 출처 판정은 최종 URL로
	return &Page{URL: resp.Request.URL.String(), Body: body}, nil
}
