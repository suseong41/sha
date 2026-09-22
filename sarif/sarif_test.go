package sarif

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/suseong41/sha/scanner"
)

func finding(code string, sev scanner.Severity) scanner.Finding {
	return scanner.Finding{
		Code: code, Class: scanner.ClassExfiltration, Title: "제목",
		Severity: sev, Line: 3, Col: 7, Evidence: "증거",
	}
}

// 등급은 출력 계약이다 — SARIF 쪽 이름도 못 박는다.
func TestLevelMapping(t *testing.T) {
	want := map[scanner.Severity]string{
		scanner.High: "error", scanner.Medium: "warning",
		scanner.Low: "note", scanner.Info: "note",
	}
	for sev, level := range want {
		log := New("0.0.0", "a.html", []scanner.Finding{finding("c", sev)}, nil)
		if got := log.Runs[0].Results[0].Level; got != level {
			t.Errorf("%v → %q, want %q", sev, got, level)
		}
		if got := log.Runs[0].Tool.Driver.Rules[0].DefaultConfiguration.Level; got != level {
			t.Errorf("%v 규칙 기본값 = %q, want %q", sev, got, level)
		}
	}
}

// GitHub 은 이 값으로 심각도를 읽는다. INFO 는 보안 경보가 아니라 비워 둔다.
func TestSecuritySeverity(t *testing.T) {
	want := map[scanner.Severity]string{
		scanner.High: "8.0", scanner.Medium: "5.0", scanner.Low: "2.0", scanner.Info: "",
	}
	for sev, val := range want {
		log := New("0.0.0", "a.html", []scanner.Finding{finding("c", sev)}, nil)
		if got := log.Runs[0].Tool.Driver.Rules[0].Properties.SecuritySeverity; got != val {
			t.Errorf("%v → %q, want %q", sev, got, val)
		}
	}
}

// 같은 규칙이 여러 번 나와도 규칙 항목은 하나다.
func TestRuleOncePerCode(t *testing.T) {
	log := New("0.0.0", "a.html", []scanner.Finding{
		finding("same", scanner.High), finding("same", scanner.High), finding("other", scanner.Low),
	}, nil)
	if n := len(log.Runs[0].Tool.Driver.Rules); n != 2 {
		t.Errorf("규칙 %d개, want 2", n)
	}
	if n := len(log.Runs[0].Results); n != 3 {
		t.Errorf("결과 %d개, want 3", n)
	}
}

// 설명이 SARIF 의 자리로 들어간다 — 74교시에 쓴 것이 여기서 쓰인다.
func TestExplanationFlowsIn(t *testing.T) {
	log := New("0.0.0", "a.html", []scanner.Finding{finding("sri-missing", scanner.Low)}, nil)
	r := log.Runs[0].Tool.Driver.Rules[0]
	if r.FullDescription == nil || r.Help == nil {
		t.Fatal("설명이 안 들어갔다")
	}
	e, _ := scanner.Explain("sri-missing")
	if r.FullDescription.Text != e.Why || r.Help.Text != e.Fix {
		t.Error("설명이 표와 다르다")
	}
}

// 설명이 없는 코드는 그 칸을 비운다 — 빈 문자열을 넣지 않는다.
func TestNoExplanationLeavesEmpty(t *testing.T) {
	log := New("0.0.0", "a.html", []scanner.Finding{finding("그런-규칙-없음", scanner.High)}, nil)
	if r := log.Runs[0].Tool.Driver.Rules[0]; r.FullDescription != nil || r.Help != nil {
		t.Error("없는 설명을 채웠다")
	}
}

// uri 는 URI 다 — 공백과 한글이 들어간 경로도 그대로 쓰면 안 된다.
func TestURIEncoded(t *testing.T) {
	log := New("0.0.0", "폴더/a b.html", []scanner.Finding{finding("c", scanner.High)}, nil)
	got := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if strings.Contains(got, " ") {
		t.Errorf("uri %q — 공백이 그대로다", got)
	}
	if got == "폴더/a b.html" {
		t.Errorf("uri %q — 인코딩되지 않았다", got)
	}
}

// 참고는 발견이 아니다 — 결과가 아니라 알림으로 간다.
func TestNotesAreNotResults(t *testing.T) {
	log := New("0.0.0", "a.html", nil, []string{"SPA 껍데기로 보임"})
	if n := len(log.Runs[0].Results); n != 0 {
		t.Errorf("참고가 결과로 들어갔다 (%d건)", n)
	}
	inv := log.Runs[0].Invocations
	if len(inv) != 1 || len(inv[0].Notifications) != 1 {
		t.Fatalf("알림이 없다: %+v", inv)
	}
	if inv[0].Notifications[0].Message.Text != "SPA 껍데기로 보임" {
		t.Error("참고 내용이 다르다")
	}
}

// 발견이 없어도 results 는 null 이 아니라 [] 다.
func TestEmptyIsNotNull(t *testing.T) {
	b, err := json.Marshal(New("0.0.0", "a.html", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"results":[]`, `"rules":[]`, `"version":"2.1.0"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("%s 가 없다: %s", want, b)
		}
	}
}

// 깨진 태그는 조용히 무시되고 Go 필드 이름이 그대로 나간다 — 되받는 구조체로는 안 보인다.
func TestEveryFieldHasJSONTag(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Ptr || rt.Kind() == reflect.Slice {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.Tag.Get("json") == "" {
				t.Errorf("%s.%s: json 태그가 없거나 깨졌다 — `%s`", rt.Name(), f.Name, f.Tag)
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(Log{}))
	if len(seen) < 10 {
		t.Errorf("타입을 %d개만 훑었다 — 걷는 코드가 멈춘 것 같다", len(seen))
	}
}
