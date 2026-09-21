package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/suseong41/sha/scanner"
	"github.com/suseong41/sha/version"
)

// map: [키]값{}
// Printf - 표준 출력 | Fprintf - 원하는 파일에 출력

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func usage(fs *flag.FlagSet) {
	out := fs.Output()
	fmt.Fprintf(out, "사용법: %s [옵션] <htmlfile> [url]\n\n", fs.Name())
	fs.PrintDefaults()
	fmt.Fprintf(out, "\n종료 코드: 0-발견 없음 1-발견 있음 2-사용법/입출력 오류")
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sha", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(fs) }
	minName := fs.String("min", "info", "최소 심각도 (info|low|medium|high)")
	className := fs.String("class", "", "분류로 거르기 (exfiltration|execution|origin|supply-chain|evasion|hardening)")
	showStats := fs.Bool("stats", false, "토큰·태그 통계도 출력")
	showVersion := fs.Bool("version", false, "버전을 찍고 끝낸다")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "sha %s\n", version.V)
		return 0
	}

	if n := fs.NArg(); n < 1 || 2 < n {
		fs.Usage()
		return 2
	}
	min, ok := scanner.ParseSeverity(*minName)
	if !ok {
		fmt.Fprintf(stderr, "알 수 없는 심각도: %q\n", *minName)
		return 2
	}

	var class scanner.Class
	filterClass := *className != ""
	if filterClass {
		c, ok := scanner.ParseClass(*className)
		if !ok {
			fmt.Fprintf(stderr, "알 수 없는 분류: %q\n", *className)
			return 2
		}
		class = c
	}

	path, pageURL := fs.Arg(0), fs.Arg(1)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	res := scanner.ScanURL(string(data), pageURL)

	var findings []scanner.Finding
	for _, f := range res.Findings {
		if f.Severity < min {
			continue
		}
		if filterClass && f.Class != class {
			continue
		}
		findings = append(findings, f)
	}
	scanner.SortBySeverity(findings)

	for _, f := range findings {
		fmt.Fprintf(stdout, "%s:%d:%d: %-6s %-13s [%s] %s\n",
			path, f.Line, f.Col, f.Severity, f.Class, f.Code, f.Evidence)
	}

	if *showStats {
		printStats(stderr, res)
	}
	fmt.Fprintf(stderr, "\n%s - 발견 %d건\n", path, len(findings))
	for _, n := range res.Notes {
		fmt.Fprintf(stderr, "참고: %s\n", n)
	}

	if len(findings) == 0 {
		return 0
	}
	return 1
}

func printStats(out io.Writer, res scanner.Result) {
	fmt.Fprintf(out, "\n토큰: %v\n", res.Tokens)
	names := make([]string, 0, len(res.Tags))
	for n := range res.Tags {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return res.Tags[names[j]] < res.Tags[names[i]] })
	fmt.Fprintln(out, "태그별 (상위 10)")
	for i, n := range names {
		if 10 <= i {
			break
		}
		fmt.Fprintf(out, " %-12s %d\n", n, res.Tags[n])
	}
}
