package fetcher

import "net/netip"

// blockedNets: 표준 라이브러리 판별 함수가 놓치는 대역.
var blockedNets = []struct {
	pfx netip.Prefix
	why string
}{
	{netip.MustParsePrefix("100.64.0.0/10"), "통신사 내부망(CGNAT)"},
	{netip.MustParsePrefix("192.0.0.0/24"), "프로토콜 전용 대역"},
	{netip.MustParsePrefix("198.18.0.0/15"), "벤치마킹 대역"},
	{netip.MustParsePrefix("240.0.0.0/4"), "예약 대역"},
	// 아래 넷은 IPv6 주소지만 실제로는 IPv4 로 간다. 전부 루프백에 닿을 수 있다.
	{netip.MustParsePrefix("::/96"), "IPv4-호환 IPv6(폐기된 표기)"},
	{netip.MustParsePrefix("64:ff9b::/96"), "NAT64"},
	{netip.MustParsePrefix("2001::/32"), "Teredo"},
	{netip.MustParsePrefix("2002::/16"), "6to4"},
}

// blockedReason(): 이 주소로 나가면 안 되는 이유.
func blockedReason(a netip.Addr) string {
	a = a.Unmap() // ::ffff:127.0.0.1 과 127.0.0.1 은 같은 곳
	switch {
	case !a.IsValid():
		return "주소가 아님"
	case a.Zone() != "":
		return "스코프 지정 주소" // "fe80::1%en0 — 내 인터페이스를 직접 가리킨다
	case a.IsLoopback():
		return "루프백"
	case a.IsPrivate():
		return "사설망"
	case a.IsLinkLocalUnicast():
		return "링크로컬(클라우드 메타데이터)"
	case a.IsMulticast():
		return "멀티캐스트"
	case a.IsUnspecified():
		return "미지정 주소"
	case !a.IsGlobalUnicast():
		return "공인 유니캐스트 아님" // 브로드캐스
	}
	for _, b := range blockedNets {
		if b.pfx.Contains(a) {
			return b.why
		}
	}
	return ""
}
