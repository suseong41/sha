package scanner

import "testing"

func TestParseSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
		ok   bool
	}{
		{"info", Info, true},
		{"LOW", Low, true},
		{" medium ", Medium, true},
		{"med", Medium, true},
		{"High", High, true},
		{"critical", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseSeverity(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("ParseSeverity(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestSeverityRoundTrip(t *testing.T) {
	for _, s := range []Severity{Info, Low, Medium, High} {
		got, ok := ParseSeverity(s.String())
		if !ok || got != s {
			t.Errorf("%v → %q → %v,%v", s, s.String(), got, ok)
		}
	}
	if got := Severity(99).String(); got != "?" {
		t.Errorf("Severity(99).String() = %q, want \"?\"", got)
	}
}
func TestSeverityOrder(t *testing.T) {
	order := []Severity{Info, Low, Medium, High}
	for i := 1; i < len(order); i++ {
		if !(order[i-1] < order[i]) {
			t.Errorf("%v < %v 이어야 한다", order[i-1], order[i])
		}
	}
}

// 규칙마다 등급을 못으로 박는다. 등급은 종료 코드(-min)와 API 의 severity 를 정하는
// 출력 계약이라, 실수로 바뀌면 조용히 남의 CI 를 통과시키거나 막는다.
// 값을 바꾸려면 재서 근거를 남기고 이 표를 함께 고친다 (57교시 · 71교시).
// allRulesHTML: 규칙 전부를 한 번에 띄우는 표본. 등급 표와 설명 표가 함께 쓴다.
const allRulesHTML = `
<title>Suspected phishing site \u2014 Cloudflare</title>
<base href="https://evil.com/">
<meta http-equiv="refresh" content="0;url=data:text/html,x">
<iframe src="https://x.com/" sandbox="allow-scripts allow-same-origin"></iframe>
<iframe src="data:text/html,x"></iframe>
<form action="http://192.168.0.1/x"><input type="password"></form>
<form action="http://login.x.example/"><input type="password" name="pw"></form>
<form action="http://localhost/login"><input type="password" name="pw2"></form>
<form action="/x"><input type="text" name="password3"></form>
<script src="//cdn.x.com/a.js"></script>
<img src="http://x.com/a.png">
<a href="javascript:alert(1)" target="_blank">z</a>
<a href="https://x.com/setup.hta">내려받기</a>
<p onclick="x()">보이지` + "​" + `않음</p>
<p>c99shell</p><input type="file">
<script>new ActiveXObject("WScript.Shell")</script>
<script>unescape("%uE8FC%u4141")</script>
<script>eval(atob(x)); fetch("https://api.telegram.org/b/x")</script>
<noscript><img src="x" alt="</noscript><b>"></noscript>
<img src="https://аpple.example/x.png">`

func TestEveryRuleSeverity(t *testing.T) {
	want := map[string]Severity{
		// HIGH — 공격자의 흔적
		"base-href-external":         High,
		"cross-origin-password-form": High,
		"data-uri-document":          High,
		"encoded-shellcode":          High,
		"exfil-channel":              High,
		"form-action-ip":             High,
		"local-system-object":        High,
		"meta-refresh-scheme":        High,
		"webshell-signature":         High,
		"mixed-script-host":          High,
		"phishing-interstitial":      High,
		// MEDIUM — 이 페이지에 실재하는 약점이고 운영자가 고칠 수 있다
		"cleartext-credentials": Medium,
		"dangerous-download":    Medium,
		"iframe-sandbox-escape": Medium,
		"javascript-url":        Medium,
		"local-credential-post": Medium,
		"noscript-breakout":     Medium,
		"obfuscated-eval":       Medium,
		"weak-password-field":   Medium,
		"resource-ip-literal":   Medium,
		// 페이지가 https 로 확인될 때만 MEDIUM — 스킴을 모르면 INFO (rules_resource_test.go)
		"mixed-content": Medium,
		// LOW — 위험의 재료이거나 다른 설명이 가능한 것
		"inline-handler": Low,
		"sri-missing":    Low,
		"zero-width":     Low,
		// INFO — 전제를 확인하지 못했거나 요즘 브라우저에서 해소된 것
		"target-blank-no-rel": Info,
	}

	seen := map[string]bool{}
	for _, f := range ScanURL(allRulesHTML, "https://page.example/").Findings {
		if w, ok := want[f.Code]; ok && f.Severity != w {
			t.Errorf("%s 의 등급 = %v, want %v", f.Code, f.Severity, w)
		}
		seen[f.Code] = true
	}
	for code := range want {
		if !seen[code] {
			t.Errorf("%s 가 발동하지 않음 — 샘플이나 규칙을 확인하라", code)
		}
	}
	// 반대 방향 — 표에 없는 코드가 조용히 지나가면 등급이 안 박힌다.
	for code := range seen {
		if _, ok := want[code]; !ok {
			t.Errorf("%s 가 표에 없음 — 규칙을 더했으면 등급도 못 박아라", code)
		}
	}
}
