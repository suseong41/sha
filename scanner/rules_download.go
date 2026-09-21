package scanner

import (
	"strings"

	"github.com/suseong41/sha/tokenizer"
)

// pathExt(): 경로 마지막 요소의 확장자 추출
func pathExt(p string) string {
	if i := strings.IndexAny(p, "?#"); 0 <= i {
		p = p[:i]
	}
	if i := strings.LastIndexByte(p, '/'); 0 <= i {
		p = p[i+1:]
	}
	i := strings.LastIndexByte(p, '.')
	if i < 0 || i == len(p)-1 {
		return ""
	}
	return p[i+1:]
}

// urlPathExt(): URL 경로의 확장자. 단, 호스트는 안봄.
func urlPathExt(rawURL string) string {
	v := normalizeURL(rawURL)
	switch {
	case strings.Contains(v, "://"):
		v = v[strings.Index(v, "://")+3:]
	case strings.HasPrefix(v, "//"):
		v = v[2:]
	default:
		return pathExt(v) // 상대 경로: 전체가 경로
	}
	i := strings.IndexByte(v, '/')
	if i < 0 {
		return "" // 경로 없음.
	}
	return pathExt(v[i:])
}

// 정상 사이트에 링크로 걸 이유가 없는 확장자.
var dangerousDownloadExts = map[string]bool{
	"hta": true, "scr": true, "pif": true, "cpl": true, "msc": true,
	"vbs": true, "vbe": true, "jse": true, "wsf": true, "wsh": true,
	"lnk": true, "reg": true, "ps1": true, "bat": true, "cmd": true,
}

func ruleDangerousDownload(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken || (tok.Name != "a" && tok.Name != "area") {
		return nil
	}
	href, ok := tok.Attr("href")
	if !ok {
		return nil
	}
	ext := urlPathExt(href)
	if !dangerousDownloadExts[ext] {
		return nil
	}
	return []Finding{{
		Code: "dangerous-download", Class: ClassExecution,
		Title:    "실행 가능한 파일로 연결되는 링크 (." + ext + ")",
		Severity: Medium, Offset: tok.Offset, Evidence: "href=" + href,
	}}
}

func ruleResourceIPLiteral(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken {
		return nil
	}
	var out []Finding
	for _, a := range tok.Attrs {
		if !isSubresource(tok.Name, a.Name) {
			continue
		}
		host := absoluteHost(a.Value)
		if !isIPLiteralHost(host) {
			continue
		}
		out = append(out, Finding{
			Code: "resource-ip-literal", Class: ClassSupplyChain,
			Title:    "하위 리소스를 IP 주소에서 로드",
			Severity: Medium, Offset: a.Offset,
			Evidence: "<" + tok.Name + " " + a.Name + "=" + a.Value + ">",
		})
	}
	return out
}
