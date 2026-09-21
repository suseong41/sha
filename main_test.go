package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/suseong41/sha/scanner"
	"github.com/suseong41/sha/version"
)

// runCLI() run 호출, stdout stderr 문자열 반환
func runCLI(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRunExitCode(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"발견 있음", []string{"testdata/malicious_sample.html", "https://bank.example.com/"}, 1},
		{"발견 없음", []string{"testdata/corpus/hn.html", "https://news.ycombinator.com/"}, 0},
		{"-min 으로 전부 걸러짐", []string{"-min", "high", "testdata/jnu_main.html", "https://www.jnu.ac.kr/"}, 0},
		{"-stats", []string{"-stats", "testdata/jnu_main.html"}, 1},
		{"-h 는 오류가 아니다", []string{"-h"}, 0},

		{"인자 없음", nil, 2},
		{"인자 3개", []string{"a", "b", "c"}, 2},
		{"없는 파일", []string{"testdata/없음.html"}, 2},
		{"잘못된 -min", []string{"-min", "critical", "testdata/jnu_main.html"}, 2},
		{"잘못된 -class", []string{"-class", "xss", "testdata/jnu_main.html"}, 2},
		{"없는 플래그", []string{"-zzz", "testdata/jnu_main.html"}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got, _, _ := runCLI(c.args...); got != c.want {
				t.Errorf("종료 코드 %d, want %d", got, c.want)
			}
		})
	}
}

func TestRunNotesAreNotFindings(t *testing.T) {
	code, out, errOut := runCLI("testdata/spa_shell.html", "https://app.example.com/")
	if code != 0 {
		t.Errorf("종료 코드 %d, want 0 — 참고가 종료 코드를 바꿨다", code)
	}
	if out != "" {
		t.Errorf("stdout 이 비어야 한다: %q", out)
	}
	if !strings.Contains(errOut, "참고:") {
		t.Errorf("stderr 에 참고가 없다: %q", errOut)
	}
}

func TestRunFilters(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		codes []string
	}{
		// 71교시에 sri-missing 이 LOW 가 되면서 이 정상 페이지에는 MEDIUM 이 하나도 남지 않는다.
		{"-min medium — 정상 페이지", []string{"-min", "medium", "testdata/jnu_main.html", "https://www.jnu.ac.kr/"},
			nil},
		{"-min medium — 악성 샘플", []string{"-min", "medium", "testdata/malicious_sample.html", "https://bank.example.com/"},
			[]string{"exfil-channel", "cross-origin-password-form", "webshell-signature", "obfuscated-eval", "javascript-url"}},
		{"-class hardening", []string{"-class", "hardening", "testdata/jnu_main.html", "https://www.jnu.ac.kr/"},
			[]string{"inline-handler", "target-blank-no-rel"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, out, _ := runCLI(c.args...)
			if len(c.codes) == 0 {
				if strings.TrimSpace(out) != "" {
					t.Fatalf("아무것도 안 나와야 하는데:\n%s", out)
				}
				return
			}
			lines := strings.Split(strings.TrimSpace(out), "\n")
			if len(lines) != len(c.codes) {
				t.Fatalf("%d줄, want %d:\n%s", len(lines), len(c.codes), out)
			}
			for i, code := range c.codes {
				if !strings.Contains(lines[i], "["+code+"]") {
					t.Errorf("%d번째 줄에 [%s] 없음: %s", i+1, code, lines[i])
				}
			}
		})
	}
}

func TestRunSortsBySeverity(t *testing.T) {
	_, out, _ := runCLI("testdata/malicious_sample.html", "https://bank.example.com/")
	if out == "" {
		t.Fatal("stdout이 비었다")
	}
	prev := scanner.High
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line) // [경로:줄:칸:, 심각도, 분류, [코드], ...]
		sev, ok := scanner.ParseSeverity(fields[1])
		if !ok {
			t.Fatalf("심각도를 읽을 수 없음: %s", line)
		}
		if prev < sev {
			t.Errorf("%v 뒤에 %v — 내림차순이 아니다", prev, sev)
		}
		prev = sev
	}
}

// -version 은 파일 인자 없이도 버전을 찍고 0 으로 끝난다.
// 자리가 틀리면(NArg 검사 뒤) 파일을 안 줬다고 2 로 끝난다.
func TestRunVersion(t *testing.T) {
	code, stdout, stderr := runCLI("-version")
	if code != 0 {
		t.Errorf("종료 코드 %d, want 0 — 파일 인자 검사보다 먼저 끝나야 함", code)
	}
	if want := "sha " + version.V + "\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr = %q — 버전은 표준 출력으로 나간다", stderr) // 파이프로 받는 값이라
	}
}

// 버전만 물었으면 스캔은 하지 않는다 — 파일을 줘도 발견을 찍지 않고 0 으로 끝난다.
func TestRunVersionSkipsScan(t *testing.T) {
	code, stdout, _ := runCLI("-version", "testdata/malicious_sample.html", "https://bank.example.com/")
	if code != 0 {
		t.Errorf("종료 코드 %d, want 0", code) // 악성 샘플이지만 스캔 안 함
	}
	if strings.Contains(stdout, "HIGH") {
		t.Errorf("버전만 물었는데 스캔함:\n%s", stdout)
	}
}
