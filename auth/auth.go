package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/1f349/lavender/database"
	"html/template"
	"net/http"
)

// State defines the currently reached authentication state
type State byte

const (
	// StateUnauthorized defines the "unauthorized" state of a session
	StateUnauthorized State = iota
	// StateBasic defines the "username and password with no OTP" user state
	// This is skipped if OTP/passkey is optional and not enabled for the user
	StateBasic
	// StateExtended defines the "logged in" user state
	StateExtended
	// StateSudo defines the "sudo" user state
	// This state is temporary and has a configurable duration
	StateSudo
)

func (s State) IsLoggedIn() bool { return s >= StateExtended }

func (s State) IsSudoAvailable() bool { return s == StateSudo }

type Provider interface {
	// AccessState defines the state at which the provider is allowed to show.
	// Some factors might be unavailable due to user preference.
	AccessState() State

	// Name defines a string value for the provider.
	Name() string

	// RenderTemplate returns HTML to embed in the page template.
	RenderTemplate(ctx context.Context, req *http.Request, user *database.User) (template.HTML, error)

	// AttemptLogin processes the login request.
	AttemptLogin(ctx context.Context, req *http.Request, user *database.User) error
}

type UserSafeError struct {
	Display  string
	Code     int
	Internal error
}

func (e UserSafeError) Error() string {
	return fmt.Sprintf("%s [%d]: %v", e.Display, e.Code, e.Internal)
}

func (e UserSafeError) Unwrap() error {
	return e.Internal
}

func BasicUserSafeError(code int, message string) UserSafeError {
	return UserSafeError{
		Code:     code,
		Display:  message,
		Internal: errors.New(message),
	}
}

func AdminSafeError(inner error) UserSafeError {
	return UserSafeError{
		Code:     http.StatusInternalServerError,
		Display:  "Internal server error",
		Internal: inner,
	}
}

type RedirectError struct {
	Target string
	Code   int
}

func (e RedirectError) TargetUrl() string { return e.Target }

func (e RedirectError) Error() string {
	return fmt.Sprintf("redirect to '%s'", e.Target)
}

type LookupUserDB interface {
	GetUser(ctx context.Context, subject string) (database.User, error)
}

func LookupUser(ctx context.Context, db LookupUserDB, subject string, user *database.User) error {
	getUser, err := db.GetUser(ctx, subject)
	if err != nil {
		return err
	}
	*user = getUser
	return nil
}
