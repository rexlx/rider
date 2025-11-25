package parser

import (
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type Contextualizer struct {
	ID          string
	Expressions map[string]*regexp.Regexp
	Checks      *PrivateChecks
}

type PrivateChecks struct {
	IgnorePrivateIPs bool
	IgnoredDomains   map[string]struct{}
	IgnoredEmails    map[string]struct{}
}

type Match struct {
	Value string
	Type  string
}

func NewContextualizer(ignoreIPs bool, ignoreDomains []string, ignoreEmails []string) *Contextualizer {
	domainMap := make(map[string]struct{}, len(ignoreDomains))
	for _, d := range ignoreDomains {
		domainMap[strings.ToLower(d)] = struct{}{}
	}

	emailMap := make(map[string]struct{}, len(ignoreEmails))
	for _, e := range ignoreEmails {
		emailMap[strings.ToLower(e)] = struct{}{}
	}

	return &Contextualizer{
		ID: "contextualizer",
		Checks: &PrivateChecks{
			IgnorePrivateIPs: ignoreIPs,
			IgnoredDomains:   domainMap,
			IgnoredEmails:    emailMap,
		},
		Expressions: map[string]*regexp.Regexp{
			"md5":      regexp.MustCompile(`([a-fA-F\d]{32})`),
			"sha1":     regexp.MustCompile(`([a-fA-F\d]{40})`),
			"sha256":   regexp.MustCompile(`([a-fA-F\d]{64})`),
			"sha512":   regexp.MustCompile(`([a-fA-F\d]{128})`),
			"ipv4":     regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`),
			"ipv6":     regexp.MustCompile(`([a-fA-F\d]{4}(:[a-fA-F\d]{4}){7})`),
			"email":    regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
			"url":      regexp.MustCompile(`((https?|ftp):\/\/[^\s/$.?#].[^\s]*)`),
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
		// Normalize to lowercase for consistent checking/sending
		cleanMatch := strings.ToLower(match)

		// 1. Check IP Privacy
		if kind == "ipv4" && c.Checks.IgnorePrivateIPs {
			if isPrivateIP(match) {
				continue
			}
		}

		// 2. Check Ignore Lists (Emails)
		if kind == "email" {
			if _, exists := c.Checks.IgnoredEmails[cleanMatch]; exists {
				continue
			}
		}

		// 3. Check Ignore Lists (Domains)
		if kind == "domain" {
			if c.isDomainIgnored(cleanMatch) {
				continue
			}

			// Extract Base Domain
			baseDomain, err := extractSecondLevelDomain(cleanMatch)
			if err == nil && baseDomain != "" {
				// LOGIC FIX: Deduplication
				// Only add the base_domain if it is DIFFERENT from the match.
				// Example: "maps.google.com" -> Adds "google.com" (Base)
				// Example: "google.com"      -> Skips Base (it's the same as the match)
				if baseDomain != cleanMatch {
					if !c.isDomainIgnored(baseDomain) {
						results = append(results, Match{Value: baseDomain, Type: "base_domain"})
					}
				}
			}
		}

		// Final Append
		// We use 'cleanMatch' for domains/emails to ensure we don't send
		// "Google.com" and "google.com" as two separate items to the API.
		finalValue := match
		if kind == "domain" || kind == "email" {
			finalValue = cleanMatch
		}

		// Safety check to ensure we never send empty strings
		if finalValue != "" {
			results = append(results, Match{Value: finalValue, Type: kind})
		}
	}
	return results
}

func (c *Contextualizer) isDomainIgnored(domain string) bool {
	current := domain
	for {
		// Check if the current segment is in the map
		if _, exists := c.Checks.IgnoredDomains[current]; exists {
			return true
		}

		// Find the next dot to strip the subdomain
		idx := strings.Index(current, ".")
		if idx == -1 {
			break // No more dots, we are done
		}

		// Move to the next level (e.g., from sub.google.com to google.com)
		current = current[idx+1:]
	}
	return false
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate()
}

func extractSecondLevelDomain(domain string) (string, error) {
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", err
	}
	return eTLDPlusOne, nil
}
