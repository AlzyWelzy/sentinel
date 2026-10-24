package collector

import "regexp"

// serviceNameRe limits watched service names to what service managers use.
// The first character can't be "-", so a name is never read as an option by
// the tools it's passed to (they're run directly, never through a shell).
var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9@._:$ -]{0,99}$`)

func validServiceName(name string) bool { return serviceNameRe.MatchString(name) }
