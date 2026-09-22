package sarif

import (
	"net/url"

	"github.com/suseong41/sha/scanner"
)

const (
	schemaURL = "https://json.schemastore.org/sarif-2.1.0.json"
	toolURL   = "https://github.com/suseong41/sha"
)

type Log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool        Tool         `json:"tool"`
	Results     []Result     `json:"results"`
	Invocations []Invocation `json:"invocations,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID                   string     `json:"id"`
	ShortDescription     Message    `json:"shortDescription"`
	FullDescription      *Message   `json:"fullDescription,omitempty"`
	Help                 *Message   `json:"help,omitempty"`
	DefaultConfiguration Config     `json:"defaultConfiguration"`
	Properties           Properties `json:"properties"`
}

type Config struct {
	Level string `json:"level"`
}

type Properties struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations"`
}

type Location struct {
	PhysicalLocation Physical `json:"physicalLocation"`
}

type Physical struct {
	ArtifactLocation Artifact `json:"artifactLocation"`
	Region           Region   `json:"region"`
}

type Artifact struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type Message struct {
	Text string `json:"text"`
}

type Invocation struct {
	ExecutionSuccessful bool           `json:"executionSuccessful"`
	Notifications       []Notification `json:"toolExecutionNotifications,omitempty"`
}

type Notification struct {
	Level   string  `json:"level"`
	Message Message `json:"message"`
}

func level(s scanner.Severity) string {
	switch s {
	case scanner.High:
		return "error"
	case scanner.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity(): GitHub가 심각도를 읽는 값.
func securitySeverity(s scanner.Severity) string {
	switch s {
	case scanner.High:
		return "8.0"
	case scanner.Medium:
		return "5.0"
	case scanner.Low:
		return "2.0"
	}
	return ""
}

// New(): 결과 하나를 SARIF로
func New(toolVersion, path string, findings []scanner.Finding, notes []string) Log {
	uri := (&url.URL{Path: path}).String()

	rules := []Rule{}
	seen := map[string]bool{}
	results := []Result{}

	for _, f := range findings {
		if !seen[f.Code] {
			seen[f.Code] = true
			r := Rule{
				ID:                   f.Code,
				ShortDescription:     Message{Text: f.Title},
				DefaultConfiguration: Config{Level: level(f.Severity)},
				Properties: Properties{
					Tags:             []string{"security", f.Class.String()},
					SecuritySeverity: securitySeverity(f.Severity),
				},
			}
			if e, ok := scanner.Explain(f.Code); ok {
				r.FullDescription = &Message{Text: e.Why}
				r.Help = &Message{Text: e.Fix}
			}
			rules = append(rules, r)
		}
		results = append(results, Result{
			RuleID:  f.Code,
			Level:   level(f.Severity),
			Message: Message{Text: f.Title + " - " + f.Evidence},
			Locations: []Location{{PhysicalLocation: Physical{
				ArtifactLocation: Artifact{URI: uri},
				Region:           Region{StartLine: f.Line, StartColumn: f.Col},
			}}},
		})
	}

	inv := Invocation{ExecutionSuccessful: true}
	for _, n := range notes {
		inv.Notifications = append(inv.Notifications, Notification{Level: "note", Message: Message{Text: n}})
	}

	return Log{
		Schema:  schemaURL,
		Version: "2.1.0",
		Runs: []Run{{
			Tool:        Tool{Driver: Driver{Name: "SHA", Version: toolVersion, InformationURI: toolURL, Rules: rules}},
			Results:     results,
			Invocations: []Invocation{inv},
		}},
	}
}
