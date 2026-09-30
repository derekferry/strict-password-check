# strictpass

A Go library for checking password strength. No third-party dependencies.

## Why

Most password strength checkers fall into one of two traps: they let almost
anything through as long as it's "long enough", or they bolt on a pile of
configurable knobs and ship with weak defaults so nobody gets locked out
during a demo. Either way, whoever integrates the library has to already
know what good password policy looks like before they can turn it on.

This library takes the opposite default. Out of the box, `Evaluate` is
strict: a real minimum length, all four character classes, no entries from
a common-password list, no obvious repeated or sequential runs, and no
reuse of the user's own identifying information. If that's too strict for
a given system, you say so explicitly with `Lenient()` — it's an opt-in
escape hatch, not a starting point.

## Install

```
go get github.com/derekferry/strict-password-check
```

## Usage

```go
package main

import (
	"fmt"

	"github.com/derekferry/strict-password-check"
)

func main() {
	result := strictpass.Evaluate("Tr0ub4dor&3")
	if !result.Passed {
		for _, reason := range result.Failures {
			fmt.Println("-", reason)
		}
		return
	}
	fmt.Println("password accepted, score:", result.Score)
}
```

Pass the account's own identifying strings so the password can't just be a
restatement of them:

```go
result := strictpass.Evaluate(candidate, strictpass.UserInputs(username, email))
```

Relax the rules only where you've decided you need to — the call site makes
that decision visible:

```go
result := strictpass.Evaluate(candidate, strictpass.Lenient())
```

`Lenient()` lowers the minimum length from 12 to 8 and the required
character classes from 4 to 3, and skips the repeated/sequential run check.
It does not skip the common-password blocklist or the user-input check —
those apply either way.

Add your own blocked passwords, such as application-specific terms or a
breach list you already have. Entries must match the whole password, ignoring
case, and apply in both modes:

```go
result := strictpass.Evaluate(candidate, strictpass.WithBlocklist("Acme2026!Launch"))
```

Override the minimum length directly if neither default fits:

```go
result := strictpass.Evaluate(candidate, strictpass.MinLength(16))
```

## Result

```go
type Result struct {
	Passed   bool
	Score    int      // 0 (worst) to 4 (best)
	Failures []string // empty when Passed is true
}
```

`Failures` is meant to be shown to the end user as-is, or translated if the
application is localized.

## Status

Early. The common-password list is a small seed list, not a serious
corpus — see the roadmap for what's planned next.
