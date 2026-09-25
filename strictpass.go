// Package strictpass checks password strength. The default rule set
// is deliberately strict; callers who need to accept weaker passwords
// (legacy systems, migrations) must opt in explicitly with Lenient.
package strictpass

import (
	"fmt"
	"strings"
	"unicode"
)

// Result describes the outcome of evaluating a password.
type Result struct {
	Passed   bool
	Score    int      // 0 (worst) to 4 (best)
	Failures []string // reasons the password did not pass; empty if Passed
}

type config struct {
	lenient    bool
	minLength  int
	userInputs []string
}

// Option configures how a password is evaluated.
type Option func(*config)

// Lenient relaxes the default rules: a shorter minimum length, fewer
// required character classes, and no check for repeated or sequential
// runs. Everything else (blocklist, user-input check) still applies.
// Use this only where strict defaults genuinely don't fit.
func Lenient() Option {
	return func(c *config) {
		c.lenient = true
	}
}

// MinLength overrides the minimum length requirement. Without it the
// default is 12 in strict mode and 8 in lenient mode.
func MinLength(n int) Option {
	return func(c *config) {
		c.minLength = n
	}
}

// UserInputs supplies context strings (username, email, site name)
// that the password must not contain. This check applies in both
// strict and lenient mode.
func UserInputs(inputs ...string) Option {
	return func(c *config) {
		c.userInputs = append(c.userInputs, inputs...)
	}
}

const (
	strictMinLength  = 12
	lenientMinLength = 8
)

// Evaluate checks a password against the rule set and returns a
// Result. By default the rules are strict; pass Lenient() to relax
// them.
func Evaluate(password string, opts ...Option) Result {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}

	minLen := cfg.minLength
	if minLen == 0 {
		if cfg.lenient {
			minLen = lenientMinLength
		} else {
			minLen = strictMinLength
		}
	}

	var failures []string

	if len(password) < minLen {
		failures = append(failures, fmt.Sprintf("must be at least %d characters", minLen))
	}

	classes := countClasses(password)
	requiredClasses := 4
	if cfg.lenient {
		requiredClasses = 3
	}
	if classes < requiredClasses {
		failures = append(failures, fmt.Sprintf("must contain at least %d of: lowercase, uppercase, digit, symbol", requiredClasses))
	}

	lower := strings.ToLower(password)
	if isCommonPassword(lower) {
		failures = append(failures, "must not be a commonly used password")
	}

	if !cfg.lenient && hasLongRun(password) {
		failures = append(failures, "must not contain long repeated or sequential runs of characters")
	}

	for _, input := range cfg.userInputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(input)) {
			failures = append(failures, "must not contain your username, email, or other identifying information")
			break
		}
	}

	return Result{
		Passed:   len(failures) == 0,
		Score:    scoreFor(len(password), classes, minLen, len(failures)),
		Failures: failures,
	}
}

func countClasses(s string) int {
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsSpace(r):
			// whitespace counts toward no class
		default:
			hasSymbol = true
		}
	}
	count := 0
	for _, b := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if b {
			count++
		}
	}
	return count
}

// hasLongRun reports whether s contains a run of 4 or more identical
// characters (e.g. "aaaa") or a monotonic sequence of 4 or more
// characters (e.g. "1234", "dcba").
func hasLongRun(s string) bool {
	const runLen = 4
	runes := []rune(s)
	repeat, seqUp, seqDown := 1, 1, 1
	for i := 1; i < len(runes); i++ {
		switch {
		case runes[i] == runes[i-1]:
			repeat++
		default:
			repeat = 1
		}
		switch {
		case runes[i] == runes[i-1]+1:
			seqUp++
		default:
			seqUp = 1
		}
		switch {
		case runes[i] == runes[i-1]-1:
			seqDown++
		default:
			seqDown = 1
		}
		if repeat >= runLen || seqUp >= runLen || seqDown >= runLen {
			return true
		}
	}
	return false
}

func scoreFor(length, classes, minLen, failureCount int) int {
	if failureCount > 0 {
		if length < minLen/2 {
			return 0
		}
		return 1
	}
	switch {
	case length >= minLen+8 && classes == 4:
		return 4
	case length >= minLen+4:
		return 3
	default:
		return 2
	}
}
