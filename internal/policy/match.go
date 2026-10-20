package policy

import "strings"

// MatchAction reports whether an IAM action pattern (with * and ?) matches a
// concrete action. Action names are case-insensitive.
func MatchAction(pattern, action string) bool {
	return match(strings.ToLower(pattern), strings.ToLower(action), false)
}

// CoversAction reports whether every action matched by narrow is also
// matched by broad. Wildcards in narrow are treated as "anything", so they
// can only be covered by a * in broad.
func CoversAction(broad, narrow string) bool {
	return match(strings.ToLower(broad), strings.ToLower(narrow), true)
}

// MatchResource reports whether a resource ARN pattern matches an ARN.
// Resource ARNs are case-sensitive.
func MatchResource(pattern, arn string) bool {
	return match(pattern, arn, false)
}

// CoversResource is the resource counterpart of CoversAction.
func CoversResource(broad, narrow string) bool {
	return match(broad, narrow, true)
}

// match is an iterative glob matcher for IAM's * and ? wildcards. When
// subsume is set, a * in s stands for any text, so only a * in p can absorb it.
func match(p, s string, subsume bool) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(p) && (p[pi] == s[si] || p[pi] == '?') && !(subsume && s[si] == '*'):
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
