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
}

type PrivateChecks struct {
	Ipv4          bool
	Ipv6          bool
	Domain        []string // List of domains to ignore (e.g. "google.com")
	PrivateEmails []string // List of email domains to ignore
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
			"md5":    regexp.MustCompile(`([a-fA-F\d]{32})`),
			"sha1":   regexp.MustCompile(`([a-fA-F\d]{40})`),
			"sha256": regexp.MustCompile(`([a-fA-F\d]{64})`),
			"sha512": regexp.MustCompile(`([a-fA-F\d]{128})`),
			"ipv4":   regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`),
			"ipv6":   regexp.MustCompile(`([a-fA-F\d]{4}(:[a-fA-F\d]{4}){7})`),
			"email":  regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
			"url":    regexp.MustCompile(`((https?|ftp):\/\/[^\s/$.?#].[^\s]*)`),
			// Kept to {2,3} to avoid false positives from long file extensions
			"domain":   regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,3})`),
			"filepath": regexp.MustCompile(`([a-zA-Z0-9.-]+\/[a-zA-Z0-9.-]+)`),
			"filename": regexp.MustCompile(`^[\w\-. ]+\.[a-zA-Z]{2,4}$`),
		},
	}
}

func (c *Contextualizer) GetMatches(text string, kind string, regex *regexp.Regexp) []Match {
	matches := regex.FindAllString(text, -1)
	var results []Match
	for _, match := range matches {
		// Check for Private IPv4
		if c.Checks.Ipv4 && isPrivateIP4(match) {
			continue
		}

		// Check for Private Emails (Ignored Domains)
		if kind == "email" && len(c.Checks.PrivateEmails) > 0 {
			if isIgnoredEmail(match, c.Checks.PrivateEmails) {
				continue
			}
		}

		if kind == "domain" {
			baseUrl := extractSecondLevelDomain(match)

			// Check if the base domain is in the ignore list
			if len(c.Checks.Domain) > 0 && isIgnoredDomain(baseUrl, c.Checks.Domain) {
				continue
			}

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

	// Specific handling for .co.uk (and other 2-part TLDs if added later)
	// If we have at least 3 parts and the last two are "co" and "uk"
	if len(parts) >= 3 {
		tld := parts[len(parts)-1]
		sld := parts[len(parts)-2]
		if tld == "uk" && sld == "co" {
			return parts[len(parts)-3] + "." + sld + "." + tld
		}
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

// Helper function to check if an email belongs to a private/ignored domain
func isIgnoredEmail(email string, ignoredDomains []string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	domain := strings.ToLower(parts[1])

	for _, ignored := range ignoredDomains {
		if strings.ToLower(ignored) == domain {
			return true
		}
	}
	return false
}

func isIgnoredDomain(domain string, ignoredDomains []string) bool {
	domain = strings.ToLower(domain)

	for _, ignored := range ignoredDomains {
		if strings.ToLower(ignored) == domain {
			return true
		}
	}
	return false
}
