package fetcher

import (
	"net/netip"
	"testing"
)

func TestBlockedReasonAllows(t *testing.T) {
	for _, s := range []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34",
		"2606:4700::1111",
		"2001:db8::1", // 문서용 대역 — Teredo(2001::/32) 와 헷갈리기 쉽다
	} {
		if why := blockedReason(netip.MustParseAddr(s)); why != "" {
			t.Errorf("%s 를 막았다: %s", s, why)
		}
	}
}

func TestBlockedReasonDenies(t *testing.T) {
	for _, s := range []string{
		// 루프백
		"127.0.0.1", "127.0.0.2", "127.1.2.3", "::1", "::ffff:127.0.0.1",
		// 사설망
		"10.0.0.1", "172.16.0.1", "192.168.0.1", "fc00::1", "fd00::1", "::ffff:10.0.0.1",
		// 클라우드 메타데이터
		"169.254.169.254", "::ffff:169.254.169.254", "fe80::1", "fe80::1%en0",
		// 그 외
		"0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255",
		// IsGlobalUnicast()가 true 주는 것들
		"240.0.0.1", "100.64.0.1", "192.0.0.1", "198.18.0.1",
		"::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::", "2001:0:7f00:1::",
		// 같은 대역을 IPv6 로 감싸면 — Unmap() 이 없으면 표를 그냥 지나간다
		"::ffff:240.0.0.1", "::ffff:100.64.0.1", "::ffff:192.0.0.1", "::ffff:198.18.0.1",
	} {
		if blockedReason(netip.MustParseAddr(s)) == "" {
			t.Errorf("%s 를 통과시켰다", s)
		}
	}
}

func TestBlockedReasonZeroAddr(t *testing.T) {
	var zero netip.Addr
	if blockedReason(zero) == "" {
		t.Error("제로값 주소를 통과시킴")
	}
}
