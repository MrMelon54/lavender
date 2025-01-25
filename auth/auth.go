package auth

import (
	"context"
	"github.com/1f349/lavender/database"
)

// State defines the currently reached authentication state
type State byte

const (
	// StateUnauthorized defines the "unauthorized" state of a session
	StateUnauthorized State = iota
	// StateBase defines the "username" only user state
	// This state is for providing a username to allow redirecting to oauth clients
	StateBase
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
