package strictpass

import "testing"

func TestStrictRejectsShortPassword(t *testing.T) {
	res := Evaluate("abc123!")
	if res.Passed {
		t.Fatalf("expected short password to fail strict mode, got Passed=true")
	}
}

func TestStrictAcceptsStrongPassword(t *testing.T) {
	res := Evaluate("Qx7!vLp9$mRt2Zw")
	if !res.Passed {
		t.Fatalf("expected strong password to pass strict mode, got failures: %v", res.Failures)
	}
	if res.Score < 3 {
		t.Fatalf("expected a high score for a strong password, got %d", res.Score)
	}
}

func TestLenientAcceptsShorterPassword(t *testing.T) {
	password := "Summer2026"

	strict := Evaluate(password)
	if strict.Passed {
		t.Fatalf("expected %q to fail strict mode", password)
	}

	lenient := Evaluate(password, Lenient())
	if !lenient.Passed {
		t.Fatalf("expected %q to pass lenient mode, got failures: %v", password, lenient.Failures)
	}
}

func TestLenientSkipsRunCheckButKeepsBlocklist(t *testing.T) {
	// A password with a long repeated run: strict rejects it for the
	// run alone, lenient does not check runs at all.
	password := "Aaaaaaaa1!"

	strict := Evaluate(password)
	if strict.Passed {
		t.Fatalf("expected %q to fail strict mode", password)
	}

	lenient := Evaluate(password, Lenient())
	if !lenient.Passed {
		t.Fatalf("expected %q to pass lenient mode, got failures: %v", password, lenient.Failures)
	}

	// The blocklist still applies in lenient mode.
	common := Evaluate("password1", Lenient())
	if common.Passed {
		t.Fatalf("expected common password to fail even in lenient mode")
	}
}

func TestUserInputsRejectedInBothModes(t *testing.T) {
	password := "john.doe99!STRONG"

	strict := Evaluate(password, UserInputs("john.doe"))
	if strict.Passed {
		t.Fatalf("expected password containing user input to fail strict mode")
	}

	lenient := Evaluate(password, Lenient(), UserInputs("john.doe"))
	if lenient.Passed {
		t.Fatalf("expected password containing user input to fail lenient mode")
	}
}

func TestWithBlocklistRejectsCustomEntries(t *testing.T) {
	password := "Qx7!vLp9$mRt2Zw"

	if res := Evaluate(password); !res.Passed {
		t.Fatalf("expected %q to pass without a custom blocklist, got: %v", password, res.Failures)
	}

	// Matching ignores case on both sides.
	for _, opts := range [][]Option{
		{WithBlocklist("qX7!VLP9$MRT2ZW")},
		{WithBlocklist("other", password)},
		{Lenient(), WithBlocklist(password)},
	} {
		res := Evaluate(password, opts...)
		if res.Passed {
			t.Fatalf("expected blocklisted password to fail")
		}
	}
}

func TestWithBlocklistAccumulatesAndIgnoresEmpty(t *testing.T) {
	opts := []Option{WithBlocklist("", "Alpha-Bravo-9!x"), WithBlocklist("Charlie-Delta-7!y")}

	for _, pw := range []string{"Alpha-Bravo-9!x", "Charlie-Delta-7!y"} {
		if Evaluate(pw, opts...).Passed {
			t.Fatalf("expected %q to be blocked", pw)
		}
	}
	if res := Evaluate("Qx7!vLp9$mRt2Zw", opts...); !res.Passed {
		t.Fatalf("unrelated password should pass, got: %v", res.Failures)
	}
}

func TestMinLengthOverride(t *testing.T) {
	res := Evaluate("Ab1!Ab1!Ab1!Ab1!Ab1!", MinLength(20))
	if len(res.Failures) > 0 && res.Score < 0 {
		t.Fatalf("unexpected negative score")
	}
	short := Evaluate("Ab1!Ab1!Ab1!", MinLength(20))
	found := false
	for _, f := range short.Failures {
		if f == "must be at least 20 characters" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected length failure with custom MinLength, got: %v", short.Failures)
	}
}
