package scanner

import "strings"

// eTLD+1을 모두 추적해야하나, PSL을 관리하기에 용량이 커, 자주 사용하는 곳만 반영.
// 미탐 너무 많아지면 https://publicsuffix.org/list/public_suffix_list.dat에서 받을 것.
// 빠지면 같은 접미사의 서로 다른 조직이 같은 곳으로 보임.
var multiLabelSuffixes = map[string]bool{
	// 한국
	"co.kr": true, "ne.kr": true, "or.kr": true, "re.kr": true,
	"pe.kr": true, "go.kr": true, "mil.kr": true, "ac.kr": true,
	// 영국·일본
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true,
	// 그 외 흔한 것
	"com.au": true, "com.cn": true, "com.br": true, "com.tw": true,
	"com.sg": true, "com.hk": true, "co.in": true, "co.nz": true,
	// 국가 도메인
	"go.jp": true, "hs.kr": true, "seoul.kr": true,
	"gov.cn": true, "org.cn": true, "com.tr": true, "org.il": true,
	// 호스팅·CDN — 같은 접미사라도 계정이 다르면 남남이다.
	// C-TAS 악성 도메인 918개 중 513개가 이 네 곳에 있었다(github.io 240 · vercel.app 214 · netlify.app 47 · framer.app 12).
	"github.io": true, "githubusercontent.com": true,
	"vercel.app": true, "netlify.app": true, "framer.app": true,
	"cloudfront.net": true, "googleapis.com": true, "dynu.net": true,
}

// / registrableDomain(): 호스트의 등록 가능 도메인(eTLD+1)을 반환.
func registrableDomain(host string) string {
	if host == "" || isIPLiteralHost(host) {
		return host
	}
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	last2 := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if multiLabelSuffixes[last2] {
		if len(parts) < 3 {
			return host
		}
		return parts[len(parts)-3] + "." + last2
	}
	return last2
}

// isSameOrg(): 두 호스트가 같은 조직에 속하는지 확인
func isSameOrg(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return registrableDomain(a) == registrableDomain(b)
}

// aggregator 같은 규칙의 반복 발견을 키별로 묶음
type aggregator struct {
	keys  []string
	items map[string]*aggItem
}

type aggItem struct {
	count    int
	firstOff int
	first    string
}

func (a *aggregator) add(key, evidence string, off int) {
	if a.items == nil {
		a.items = map[string]*aggItem{}
	}
	it, ok := a.items[key]
	if !ok {
		it = &aggItem{firstOff: off, first: evidence}
		a.items[key] = it
		a.keys = append(a.keys, key)
	}
	it.count++
}
