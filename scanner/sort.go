package scanner

import "sort"

// SortBySeverity(): 심각도 내림차순
func SortBySeverity(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[j].Severity < fs[i].Severity })
}
