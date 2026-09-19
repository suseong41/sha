package scanner

import "testing"

func TestParseClass(t *testing.T) {
	cases := []struct {
		in   string
		want Class
		ok   bool
	}{
		{"exfiltration", ClassExfiltration, true},
		{"EXECUTION", ClassExecution, true},
		{" supply-chain ", ClassSupplyChain, true},
		{"origin", ClassOrigin, true},
		{"evasion", ClassEvasion, true},
		{"hardening", ClassHardening, true},
		{"없는분류", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseClass(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("ParseClass(%q) = %v,%v want %v,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// String() 과 ParseClass 가 서로의 역이어야 한다.
func TestClassRoundTrip(t *testing.T) {
	all := []Class{ClassExfiltration, ClassExecution, ClassOrigin,
		ClassSupplyChain, ClassEvasion, ClassHardening}
	for _, c := range all {
		got, ok := ParseClass(c.String())
		if !ok || got != c {
			t.Errorf("%v → %q → %v,%v", c, c.String(), got, ok)
		}
	}
}

// 모든 규칙이 Class 를 부여받았는지 확인한다.
// Class 의 제로값이 ClassExfiltration 이라, 부여를 빠뜨리면 조용히 그쪽으로 분류된다.
func TestEveryRuleHasClass(t *testing.T) {
	const html = `
<base href="https://evil.com/">
<meta http-equiv="refresh" content="0;url=data:text/html,x">
<iframe src="https://x.com/" sandbox="allow-scripts allow-same-origin"></iframe>
<iframe src="data:text/html,x"></iframe>
<form action="http://192.168.0.1/x"><input type="password"></form>
<script src="//cdn.x.com/a.js"></script>
<img src="http://x.com/a.png">
<a href="javascript:alert(1)" target="_blank">z</a>
<p onclick="x()">보이지` + "​" + `않음</p>
<p>c99shell</p><input type="file">
<script>new ActiveXObject("WScript.Shell")</script>
<script>eval(atob(x)); fetch("https://api.telegram.org/b/x")</script>`

	want := map[string]Class{
		"base-href-external":         ClassOrigin,
		"meta-refresh-scheme":        ClassExecution,
		"iframe-sandbox-escape":      ClassOrigin,
		"data-uri-document":          ClassExecution,
		"form-action-ip":             ClassExfiltration,
		"cross-origin-password-form": ClassExfiltration,
		"sri-missing":                ClassSupplyChain,
		"mixed-content":              ClassSupplyChain,
		"javascript-url":             ClassExecution,
		"target-blank-no-rel":        ClassHardening,
		"inline-handler":             ClassHardening,
		"zero-width":                 ClassEvasion,
		"webshell-signature":         ClassExecution,
		"local-system-object":        ClassExecution,
		"obfuscated-eval":            ClassEvasion,
		"exfil-channel":              ClassExfiltration,
	}

	seen := map[string]bool{}
	for _, f := range ScanURL(html, "https://a.com/").Findings {
		if f.Class.String() == "?" {
			t.Errorf("%s 의 Class 가 유효하지 않음", f.Code)
		}
		if w, ok := want[f.Code]; ok && f.Class != w {
			t.Errorf("%s 의 Class = %v, want %v", f.Code, f.Class, w)
		}
		seen[f.Code] = true
	}
	for code := range want {
		if !seen[code] {
			t.Errorf("%s 가 발동하지 않음 — 샘플이나 규칙을 확인하라", code)
		}
	}
}
