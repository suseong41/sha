package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// -sarif 는 사람이 읽는 줄 대신 JSON 하나를 stdout 으로 낸다.
func TestSARIFOutput(t *testing.T) {
	code, out, _ := runCLI("-sarif", "testdata/malicious_sample.html", "https://bank.example.com/")
	if code != 1 {
		t.Errorf("종료 코드 %d, want 1 — 발견이 있으면 1 은 그대로다", code)
	}
	if strings.Contains(out, "HIGH   exfiltration") {
		t.Error("사람이 읽는 줄이 함께 나왔다")
	}

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("JSON 이 아니다: %v", err)
	}
	if log.Version != "2.1.0" || log.Schema == "" {
		t.Errorf("version=%q schema=%q", log.Version, log.Schema)
	}
	if len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "SHA" {
		t.Fatalf("runs 가 이상하다: %+v", log.Runs)
	}
	if len(log.Runs[0].Results) == 0 || len(log.Runs[0].Tool.Driver.Rules) == 0 {
		t.Fatal("결과가 비었다")
	}
	r := log.Runs[0].Results[0]
	if r.Level != "error" {
		t.Errorf("첫 결과 level=%q — 정렬 뒤 HIGH 가 먼저다", r.Level)
	}
	if got := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "testdata/malicious_sample.html" {
		t.Errorf("uri %q", got)
	}
	if r.Locations[0].PhysicalLocation.Region.StartLine == 0 {
		t.Error("줄 번호가 0 이다")
	}
}

// 발견이 없어도 올바른 SARIF 를 낸다 — CI 가 빈 결과를 올릴 수 있어야 한다.
func TestSARIFEmpty(t *testing.T) {
	code, out, _ := runCLI("-sarif", "-min", "high", "testdata/jnu_main.html", "https://www.jnu.ac.kr/")
	if code != 0 {
		t.Errorf("종료 코드 %d, want 0", code)
	}
	if !strings.Contains(out, `"results": []`) {
		t.Errorf("빈 결과가 [] 가 아니다: %s", out)
	}
	var any map[string]any
	if err := json.Unmarshal([]byte(out), &any); err != nil {
		t.Fatalf("JSON 이 아니다: %v", err)
	}
}

// -min 과 -class 는 SARIF 에도 그대로 걸린다.
func TestSARIFRespectsFilters(t *testing.T) {
	_, all, _ := runCLI("-sarif", "testdata/malicious_sample.html", "https://bank.example.com/")
	_, high, _ := runCLI("-sarif", "-min", "high", "testdata/malicious_sample.html", "https://bank.example.com/")
	if len(high) >= len(all) {
		t.Error("-min high 인데 결과가 줄지 않았다")
	}
	if strings.Contains(high, `"level": "warning"`) {
		t.Error("-min high 인데 MEDIUM 이 남았다")
	}
}
