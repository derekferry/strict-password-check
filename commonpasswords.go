package strictpass

// commonPasswords is a seed list of widely published weak passwords.
// It is intentionally small for now; a later commit will replace it
// with a much larger embedded list (see README roadmap).
var commonPasswords = map[string]bool{
	"password":  true,
	"password1": true,
	"passw0rd":  true,
	"123456":    true,
	"123456789": true,
	"12345678":  true,
	"1234567":   true,
	"qwerty":    true,
	"qwerty123": true,
	"letmein":   true,
	"welcome":   true,
	"welcome1":  true,
	"admin":     true,
	"iloveyou":  true,
	"monkey":    true,
	"dragon":    true,
	"football":  true,
	"baseball":  true,
	"trustno1":  true,
	"abc123":    true,
	"111111":    true,
	"123123":    true,
	"sunshine":  true,
	"princess":  true,
	"login":     true,
	"solo":      true,
	"master":    true,
	"shadow":    true,
	"superman":  true,
	"whatever":  true,
}

func isCommonPassword(lower string) bool {
	return commonPasswords[lower]
}
