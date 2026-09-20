package version

import (
	"regexp"
	"testing"
)

// 태그는 v0.1.0, 상수는 0.1.0 — 앞에 v 를 붙이면 배포 워크플로의 대조가 깨진다.
var semver = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func TestVersionFormat(t *testing.T) {
	if !semver.MatchString(V) {
		t.Errorf("V = %q — 숫자.숫자.숫자 여야 함 (v 를 붙이지 않는다)", V)
	}
}
