package scanner

import "testing"

const cfBlock = `<html><head><title>Attention Required! | Cloudflare</title></head>
<body><h1>Access denied</h1><p>Cloudflare Ray ID: 8a1b2c3d4e5f</p></body></html>`

const cfPhish = `<html><head><title>Suspected Phishing Site | Cloudflare</title></head>
<body><p>This website has been reported. Cloudflare Ray ID: 8a1b</p></body></html>`

func TestInterstitialNotes(t *testing.T) {
	cases := []struct {
		name, html string
		wantNotes  int
	}{
		{"정상페이지", `<html><body><h1>안녕</h1><p>내용이 있다</p></body></html>`, 0},
		{"cloudflare만언급", `<body><p>우리는 Cloudflare 를 씁니다</p></body>`, 0},
		{"rayid만", `<body><p>Ray ID: abc</p></body>`, 0},
		{"WAF차단", cfBlock, 1},
		{"피싱경고", cfPhish, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := len(Scan(c.html).Notes); got != c.wantNotes {
				t.Errorf("Notes %d개, want %d개", got, c.wantNotes)
			}
		})
	}
}

func TestPhishingInterstitialFinding(t *testing.T) {
	if n := countCode(cfPhish, "https://evil.com/", "phishing-interstitial"); n != 1 {
		t.Errorf("피싱 경고 → %d건, want 1건", n)
	}
	// WAF 차단은 대상에 대한 판정이 아니므로 발견이 아니다
	if n := countCode(cfBlock, "https://a.com/", "phishing-interstitial"); n != 0 {
		t.Errorf("WAF 차단 → %d건, want 0건", n)
	}
	if n := countCode(`<body><p>정상</p></body>`, "https://a.com/", "phishing-interstitial"); n != 0 {
		t.Errorf("정상 → %d건, want 0건", n)
	}
	// WAF 차단은 Notes 만 나오고 Findings 는 비어야 한다
	if fs := Scan(cfBlock).Findings; len(fs) != 0 {
		t.Errorf("WAF 차단의 Findings = %d건, want 0건", len(fs))
	}
}

func TestLocalCredentialPost(t *testing.T) {
	const code = "local-credential-post"
	cases := []struct {
		name, html string
		want       int
	}{
		{"정상상대경로", `<form action="/login"><input type=password></form>`, 0},
		{"정상도메인", `<form action="https://a.com/x"><input type=password></form>`, 0},
		{"비밀번호없음", `<form action="http://localhost/x"><input type=text></form>`, 0},
		{"경로에localhost", `<form action="/localhost/x"><input type=password></form>`, 0},
		{"localhost", `<form action="http://localhost:8080/x"><input type=password></form>`, 1},
		{"루프백IP", `<form action="http://127.0.0.1/x"><input type=password></form>`, 1},
		{"file", `<form action="file:///tmp/x"><input type=password></form>`, 1},
		{"formaction루프백", `<form action="/login"><input type=password><button formaction="http://127.0.0.1:8080/">x</button></form>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "https://a.com/", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}
