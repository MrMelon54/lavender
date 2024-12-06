package providers

import (
	"context"
	"database/sql"
	"errors"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/database"
	"net/http"
)

type basicLoginDB interface {
	auth.LookupUserDB
	CheckLogin(ctx context.Context, un, pw string) (database.CheckLoginResult, error)
}

var _ auth.Provider = (*BasicLogin)(nil)

type BasicLogin struct {
	DB basicLoginDB
}

func (b *BasicLogin) Factor() auth.State { return FactorBasic }

func (b *BasicLogin) Name() string { return "basic" }

func (b *BasicLogin) RenderData(ctx context.Context, req *http.Request, user *database.User, data map[string]any) error {
	data["username"] = req.FormValue("username")
	return nil
}

func (b *BasicLogin) AttemptLogin(ctx context.Context, req *http.Request, user *database.User) error {
	un := req.FormValue("username")
	pw := req.FormValue("password")
	if len(pw) < 8 {
		return auth.BasicUserSafeError(http.StatusBadRequest, "Password too short")
	}

	login, err := b.DB.CheckLogin(ctx, un, pw)
	switch {
	case err == nil:
		return auth.lookupUser(ctx, b.DB, login.Subject, false, user)
	case errors.Is(err, sql.ErrNoRows):
		return auth.BasicUserSafeError(http.StatusForbidden, "Username or password is invalid")
	default:
		return err
	}
}
