package parser

import (
	"reflect"
	"testing"
)

// setupContextualizer creates a Contextualizer with specific settings for tests
func setupContextualizer() *Contextualizer {
	return NewContextualizer(
		true, // ignorePrivateIPs: true
		[]string{"testignore.com", "sub.ignored.com"},
		[]string{"user@ignore.com"},
	)
}

// --- Basic Initialization Tests ---

func TestNewContextualizer(t *testing.T) {
	c := NewContextualizer(
		true,
		[]string{"EXAMPLE.com", "test.org"},
		[]string{"User@Email.com"},
	)

	if c.ID != "contextualizer" {
		t.Errorf("Expected ID 'contextualizer', got %s", c.ID)
	}

	if !c.Checks.IgnorePrivateIPs {
		t.Errorf("Expected IgnorePrivateIPs to be true")
	}

	if _, exists := c.Checks.IgnoredDomains["example.com"]; !exists {
		t.Errorf("Expected ignored domain 'example.com' (normalized) not found")
	}

	if _, exists := c.Checks.IgnoredEmails["user@email.com"]; !exists {
		t.Errorf("Expected ignored email 'user@email.com' (normalized) not found")
	}

	if len(c.Expressions) == 0 {
		t.Errorf("Expected Expressions to be initialized")
	}
}

// --- New Feature: Refanging Tests ---

func TestRefang(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		name     string
	}{
		{"hxxp://malware[.]site", "http://malware.site", "URL with brackets"},
		{"user(at)domain{.}com", "user@domain.com", "Email with parens/braces"},
		{"192.168.1[:]1", "192.168.1:1", "IP with colon brackets"},
		{"hXXps://site(.)org", "https://site.org", "HTTPS case sensitivity"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Refang(tt.input); got != tt.expected {
				t.Errorf("Refang() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// --- Domain & IP Logic Tests ---

func TestIsDomainIgnored(t *testing.T) {
	c := setupContextualizer()

	tests := []struct {
		domain   string
		expected bool
		name     string
	}{
		{"testignore.com", true, "Exact match"},
		{"sub.testignore.com", true, "Subdomain of ignored domain"},
		{"test.org", false, "Not ignored"},
		{"sub.ignored.com", true, "Exact subdomain match"},
		{"another.sub.ignored.com", true, "Further subdomain"},
		{"testignore.co.uk", false, "Different TLD"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if c.isDomainIgnored(tt.domain) != tt.expected {
				t.Errorf("isDomainIgnored(%s): expected %v, got %v", tt.domain, tt.expected, !tt.expected)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
		name     string
	}{
		{"192.168.1.1", true, "Class C private"},
		{"10.0.0.1", true, "Class A private"},
		{"172.16.0.1", true, "Class B private start"},
		{"172.31.255.255", true, "Class B private end"},
		{"127.0.0.1", true, "Loopback"},
		{"169.254.1.1", true, "Link local"},
		{"8.8.8.8", false, "Public IP"},
		{"256.256.256.256", false, "Invalid IP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isPrivateIP(tt.ip) != tt.expected {
				t.Errorf("isPrivateIP(%s): expected %v, got %v", tt.ip, tt.expected, !tt.expected)
			}
		})
	}
}

func TestExtractSecondLevelDomain(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
		err      bool
		name     string
	}{
		{"sub.example.com", "example.com", false, "Standard TLD"},
		{"sub.example.co.uk", "example.co.uk", false, "eTLD+1 TLD"},
		{"google.com", "google.com", false, "Base domain"},
		{"localhost", "", true, "Not a domain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := extractSecondLevelDomain(tt.domain)
			if (err != nil) != tt.err {
				t.Errorf("extractSecondLevelDomain(%s) error mismatch", tt.domain)
				return
			}
			if result != tt.expected {
				t.Errorf("extractSecondLevelDomain(%s): expected %s, got %s", tt.domain, tt.expected, result)
			}
		})
	}
}

// --- Regex & Extraction Tests ---

func TestRegexExpressions(t *testing.T) {
	tests := []struct {
		kind  string
		text  string
		match bool
	}{
		{"md5", "0bc27d34f318cdf8acf1dde835e4f8eb", true},
		{"sha256", "7b20ddeb26e16c050a7fcfb23f7e5e3889712ca75daa563051b73ef5d31ad458", true},
		{"ipv4", "192.168.1.1", true},
		{"email", "user.name+tag@sub.domain.com", true},
		{"url", "http://example.com/path?q=1", true},
		{"domain", "test.sub.example.co.uk", true},
		{"filepath", "path/to/file.txt", true},
		{"filename", "config.json", true},
		{"cve", "CVE-2024-1234", true},
	}

	c := setupContextualizer()
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			regex := c.Expressions[tt.kind]
			if regex.MatchString(tt.text) != tt.match {
				t.Errorf("Regex for %s failed on text: %s", tt.kind, tt.text)
			}
		})
	}
}

func TestGetMatches(t *testing.T) {
	c := setupContextualizer()

	tests := []struct {
		name     string
		kind     string
		text     string
		expected []Match
	}{
		{
			name: "IPv4 Filter Private",
			kind: "ipv4",
			text: "Public: 8.8.8.8, Private: 192.168.1.1",
			expected: []Match{
				{Value: "8.8.8.8", Type: "ipv4"},
			},
		},
		{
			name: "Email Filter Ignored",
			kind: "email",
			text: "Valid: user@example.com, Ignored: user@ignore.com",
			expected: []Match{
				{Value: "user@example.com", Type: "email"},
			},
		},
		{
			name: "URL Trailing Cleanup",
			kind: "url",
			text: "Visit http://example.com/path/.",
			expected: []Match{
				{Value: "http://example.com/path", Type: "url"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := c.GetMatches(tt.text, tt.kind, c.Expressions[tt.kind])
			if !reflect.DeepEqual(actual, tt.expected) {
				t.Errorf("GetMatches mismatch\nActual: %+v\nExpected: %+v", actual, tt.expected)
			}
		})
	}
}

func TestExtractAll(t *testing.T) {
	c := setupContextualizer()

	t.Run("Comprehensive Content", func(t *testing.T) {
		input := "Check hxxp://malware[.]site/path and 192.168.1.1. Also user(at)test.org."
		results := c.ExtractAll(input)

		if results["url"][0].Value != "http://malware.site/path" {
			t.Errorf("Refanging/Extraction failed for URL: %s", results["url"][0].Value)
		}
		if results["email"][0].Value != "user@test.org" {
			t.Errorf("Refanging/Extraction failed for Email: %s", results["email"][0].Value)
		}
		// 192.168.1.1 should be ignored (Private)
		for _, ip := range results["ipv4"] {
			if ip.Value == "192.168.1.1" {
				t.Error("Private IP was not ignored in ExtractAll")
			}
		}
	})

	t.Run("Hash Collision Prevention", func(t *testing.T) {
		// SHA256 should not trigger MD5 matches
		input := "Hash: 7b20ddeb26e16c050a7fcfb23f7e5e3889712ca75daa563051b73ef5d31ad458"
		results := c.ExtractAll(input)

		if len(results["sha256"]) != 1 {
			t.Errorf("Expected 1 SHA256, got %d", len(results["sha256"]))
		}
		if len(results["md5"]) > 0 {
			t.Error("MD5 incorrectly extracted from SHA256 string")
		}
	})

	t.Run("URL vs Filepath Protection", func(t *testing.T) {
		input := "Download from http://example.com/path/to/file.exe"
		results := c.ExtractAll(input)

		// Filepath parser should not grab segments already inside a URL
		for _, fp := range results["filepath"] {
			if fp.Value == "path/to" {
				t.Error("Filepath incorrectly extracted from within URL string")
			}
		}
	})
}

func TestIsLikelyFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"malware.exe", true},
		{"script.sh", true},
		{"archive.zip", true},
		{"main.go", true},
		{"google.com", false},
		{"www.example.zip", false},
		{"https://example.zip", false},
		{"http://test.com/file.txt", false},
		{"./script.sh", true},
		{"my_data.bin", true},
		{"app.v1.2.tar.gz", true},
		{"research.gov", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isLikelyFilename(tt.input); got != tt.expected {
				t.Errorf("isLikelyFilename(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractAll_DomainVsFile(t *testing.T) {
	c := setupContextualizer()
	input := "Check update.exe on download.site.com, script.sh, archive.zip and output.log"

	results := c.ExtractAll(input)

	// Ensure domains are correct
	foundDomain := false
	for _, m := range results["domain"] {
		if m.Value == "download.site.com" {
			foundDomain = true
		}
		if m.Value == "update.exe" || m.Value == "output.log" || m.Value == "script.sh" || m.Value == "archive.zip" {
			t.Errorf("Collision: %s incorrectly matched as domain", m.Value)
		}
	}
	if !foundDomain {
		t.Error("Failed to find valid domain")
	}
}

func TestNoiseFiltering(t *testing.T) {
	c := setupContextualizer()

	noisySamples := []string{
		"session-2283.scope",
		"session-2282.scope",
		"83.827008ms",
		"66.284344ms",
		"18.428305ms",
		"1.129422ms",
		"1.031s",
		"9.6m",
		"11.062s",
		"proc/1177976",
		"proc/1158878",
		"/proc/1141751",
		"timedate1.service",
		"dbus-org.freedesktop.timedate1.service",
		"systemd-timedated.service",
		"org.freedesktop",
		"org.freedesktop.timedate1",
		"app-layer.protocols.snmp.detection",
		"snmp.version",
		"snmp.detection",
		"app-layer.protocols.sip.detection",
		"sip.detection",
		"fail2ban.actions",
		"rules/suricata",
		"usr/share",
		"run/ips",
		"suricata/lib",
		"research/25",
		"post/ve-cve-2026-0826-critical-unauthenticated-stack-buffer-overflow-hp-poly-vvx-trio-voip-phones-fixed",
		"j/operation-zero-disco-cisco-snmp-vulnerability-exploit.html",
	}

	for _, sample := range noisySamples {
		t.Run("Noise_"+sample, func(t *testing.T) {
			res := c.ExtractAll("log entry containing " + sample + " in output")
			for kind, matches := range res {
				for _, m := range matches {
					if m.Value == sample {
						t.Errorf("Expected noisy value %q to be filtered out of %s, but got match", sample, kind)
					}
				}
			}
		})
	}

	t.Run("ValidIOCsPreserved", func(t *testing.T) {
		legit := "Detected 1.214.214.114 connecting to trendmicro.com and www.rapid7.com via config/iface.yaml using ubnt-idsips-daemon.so"
		res := c.ExtractAll(legit)

		expectedMatches := map[string]string{
			"ipv4":     "1.214.214.114",
			"domain":   "trendmicro.com",
			"filepath": "config/iface.yaml",
			"filename": "ubnt-idsips-daemon.so",
		}

		for kind, expectedVal := range expectedMatches {
			found := false
			for _, m := range res[kind] {
				if m.Value == expectedVal {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected legitimate IOC %q in %s, but not found. Got: %+v", expectedVal, kind, res[kind])
			}
		}
	})
}
