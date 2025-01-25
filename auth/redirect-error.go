package auth

import "fmt"

type RedirectError struct {
	Target string
	Code   int
}

func (e RedirectError) TargetUrl() string { return e.Target }

func (e RedirectError) Error() string {
	return fmt.Sprintf("redirect to '%s'", e.Target)
}
