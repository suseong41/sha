package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// 실제 웹에서 curl로 받아온 정상 페이지들.
var corpus = []struct {
	file  string // testdata/ 기준 상대 경로
	url   string // 그 페이지의 실제 URL
	total int
}{
	{"jnu_main.html", "https://www.jnu.ac.kr/", 3},
	{"corpus/hn.html", "https://news.ycombinator.com/", 0},
	{"corpus/go.html", "https://go.dev/", 2},
	{"corpus/namuwiki.html", "https://namu.wiki/", 2},
	{"corpus/seoulsi.html", "https://www.seoul.go.kr/", 4},
	{"corpus/gyeonggi.html", "https://www.gg.go.kr/", 4},
	{"corpus/11st.html", "https://www.11st.co.kr/", 5},
	{"corpus/gmarket.html", "https://www.gmarket.co.kr/", 0},
	{"corpus/lotteon.html", "https://www.lotteon.com/", 1},
	{"corpus/github_login.html", "https://github.com/login", 1},
	{"corpus/inven_login.html", "https://member.inven.co.kr/", 1},
	{"corpus/nexon_login.html", "https://nxlogin.nexon.com/", 1},
	{"corpus/wikipedia_ko.html", "https://ko.wikipedia.org/wiki/HTML", 0},
	{"corpus/donga.html", "https://www.donga.com/", 6},
	{"corpus/bbc.html", "https://www.bbc.com/news", 5},
	{"corpus/naver.html", "https://www.naver.com/", 3},
	{"corpus/neverssl.html", "http://neverssl.com/", 0},
}

func TestCorpusNoFalsePositive(t *testing.T) {
	for _, c := range corpus {
		t.Run(c.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "testdata", c.file))
			if err != nil {
				t.Fatal(err)
			}
			res := ScanURL(string(data), c.url)

			for _, f := range res.Findings {
				if f.Severity == High {
					t.Errorf("정상 페이지에 HIGH — 오탐: %d행 [%s] %s", f.Line, f.Code, f.Evidence)
				}
			}
			if len(res.Findings) != c.total {
				t.Errorf("발견 %d건, want %d — 규칙을 바꿨다면 표를 갱신하라", len(res.Findings), c.total)
			}
		})
	}
}

func TestMaliciousSampleDetected(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "malicious_sample.html"))
	if err != nil {
		t.Fatal(err)
	}
	res := ScanURL(string(data), "https://bank.example.com/")

	high := 0
	for _, f := range res.Findings {
		if f.Severity == High {
			high++
		}
	}
	if high < 3 {
		t.Errorf("HIGH %d건, 최소 3건이어야 한다 — 미탐", high)
	}
	if len(res.Findings) != 5 {
		t.Errorf("발견 %d건, want 5", len(res.Findings))
	}
}
