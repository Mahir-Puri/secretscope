// Package detect finds credentials that appear as plaintext values in Kubernetes
// environment variables. It mirrors the detection ideas used by the Rust
// scanner: known key formats plus an entropy check on values whose variable
// name looks sensitive. It never returns or logs the raw value; callers get a
// credential type and a redacted form only.
package detect

import (
	"math"
	"regexp"
	"strings"
)

var (
	awsKey       = regexp.MustCompile(`\b((?:AKIA|ASIA)[0-9A-Z]{16})\b`)
	githubToken  = regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[0-9a-zA-Z_]{40,})\b`)
	privateKey   = regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`)
	sensitiveVar = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth|credential|private[_-]?key)`)
)

// EntropyThreshold is the default bits-per-character cutoff for the generic
// detector. It matches the scanner's default.
const EntropyThreshold = 4.2

// Finding describes what was matched without exposing the secret.
type Finding struct {
	CredentialType string
	Redacted       string
}

// Inspect reports whether the value of environment variable name looks like a
// credential. The second return is nil when nothing was detected.
func Inspect(name, value string) *Finding {
	if value == "" {
		return nil
	}
	switch {
	case awsKey.MatchString(value):
		return &Finding{"aws_access_key_id", redact(value)}
	case githubToken.MatchString(value):
		return &Finding{"github_token", redact(value)}
	case privateKey.MatchString(value):
		return &Finding{"private_key", "PEM private key block"}
	}
	if sensitiveVar.MatchString(name) && len(value) >= 12 && !isPlaceholder(value) &&
		shannon(value) >= EntropyThreshold {
		return &Finding{"high_entropy_secret", redact(value)}
	}
	return nil
}

func isPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, n := range []string{"example", "changeme", "your-", "your_", "placeholder", "redacted", "xxxx", "dummy", "sample", "todo"} {
		if strings.Contains(l, n) {
			return true
		}
	}
	return strings.HasPrefix(v, "$") || strings.HasPrefix(v, "${") || strings.HasPrefix(v, "{{") || strings.HasPrefix(v, "<")
}

func redact(s string) string {
	r := []rune(s)
	if len(r) <= 8 {
		return strings.Repeat("*", len(r))
	}
	mask := len(r) - 8
	if mask > 12 {
		mask = 12
	}
	return string(r[:4]) + strings.Repeat("*", mask) + string(r[len(r)-4:])
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, c := range s {
		counts[c]++
	}
	n := float64(len([]rune(s)))
	var e float64
	for _, c := range counts {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}
