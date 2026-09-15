package fetcher

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
)

// Fetcher: SSRF를 막는 HTTP 수집기
type Fetcher struct {
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
			return nil, fmt.Errorf("%s(%s) 로는 접속하지 않는다: %s", host, ip, why)
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

// Get(): url을 가져온다. http(s)만
func (f *Fetcher) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if s := req.URL.Scheme; s != "http" && s != "https" {
		return nil, fmt.Errorf("%q: http/https 만 가져온다", s)
	}
	//tmzosakek to Transport를 쓴다.
	c := &http.Client{Transport: &http.Transport{DialContext: f.dialChecked}}
	return c.Do(req)
}
