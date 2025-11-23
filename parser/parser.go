package parser

import (
	"regexp"
	"strconv"
	"strings"
)

type Contextualizer struct {
	ID          string
	Expressions map[string]*regexp.Regexp
	Checks      *PrivateChecks
	// context     []string
}

type PrivateChecks struct {
	Ipv4   bool
	Ipv6   bool
	Domain bool
}

type Match struct {
	Value string
	Type  string
}

func NewContextualizer(checks *PrivateChecks) *Contextualizer {
	return &Contextualizer{
		Checks: checks,
		ID:     "contextualizer",
		Expressions: map[string]*regexp.Regexp{
			"md5":      regexp.MustCompile(`([a-fA-F\d]{32})`),
			"sha1":     regexp.MustCompile(`([a-fA-F\d]{40})`),
			"sha256":   regexp.MustCompile(`([a-fA-F\d]{64})`),
			"sha512":   regexp.MustCompile(`([a-fA-F\d]{128})`),
			"ipv4":     regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`),
			"ipv6":     regexp.MustCompile(`([a-fA-F\d]{4}(:[a-fA-F\d]{4}){7})`),
			"email":    regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
			"url":      regexp.MustCompile(`((https?|ftp):\/\/[^\s/$.?#].[^\s]*)`),
			"domain":   regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
			"filepath": regexp.MustCompile(`([a-zA-Z0-9.-]+\/[a-zA-Z0-9.-]+)`),
			"filename": regexp.MustCompile(`^[\w\-. ]+\.[a-zA-Z]{2,4}$`),
		},
	}
}

func (c *Contextualizer) GetMatches(text string, kind string, regex *regexp.Regexp) []Match {
	matches := regex.FindAllString(text, -1)
	var results []Match
	for _, match := range matches {
		if c.Checks.Ipv4 && isPrivateIP4(match) {
			continue
		}
		if kind == "domain" {
			baseUrl := extractSecondLevelDomain(match)
			if baseUrl != "" {
				results = append(results, Match{Value: baseUrl, Type: "base_domain"})
			}
		}
		results = append(results, Match{Value: match, Type: kind})
	}
	return results
}

func extractSecondLevelDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func isPrivateIP4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	first, _ := strconv.Atoi(parts[0])
	second, _ := strconv.Atoi(parts[1])
	if first == 10 {
		return true
	}
	if first == 172 && second >= 16 && second <= 31 {
		return true
	}
	if first == 192 && second == 168 {
		return true
	}
	return false
}
