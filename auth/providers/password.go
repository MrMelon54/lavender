package providers

import (
	"context"
	"database/sql"
	"errors"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/database"
	"net/http"
)

type passwordLoginDB interface {
	auth.LookupUserDB
	CheckLogin(ctx context.Context, un, pw string) (database.CheckLoginResult, error)
}

var (
	_ auth.Provider = (*PasswordLogin)(nil)
	_ auth.Form     = (*PasswordLogin)(nil)
)

type PasswordLogin struct {
	DB passwordLoginDB
}

func (b *PasswordLogin) AccessState() auth.State { return auth.StateBase }

func (b *PasswordLogin) Name() string { return "password" }

func (b *PasswordLogin) RenderTemplate(ctx authContext.TemplateContext) error {
	// TODO(melon): rewrite this
	req := ctx.Request()
	un := req.FormValue("login")
	redirect := req.FormValue("redirect")
	if redirect == "" {
		redirect = "/"
	}
	ctx.Render(struct {
		UserEmail string
		Redirect  string
	}{
		UserEmail: un,
		Redirect:  redirect,
	})
	return nil
}

func (b *PasswordLogin) AttemptLogin(ctx authContext.FormContext) error {
	req := ctx.Request()
	un := req.FormValue("username")
	pw := req.FormValue("password")
	if len(pw) < 8 {
		return auth.BasicUserSafeError(http.StatusBadRequest, "Password too short")
	}

	login, err := b.DB.CheckLogin(ctx.Context(), un, pw)
	switch {
	case err == nil:
		return auth.LookupUser(ctx.Context(), b.DB, login.Subject, ctx.User())
	case errors.Is(err, sql.ErrNoRows):
		return auth.BasicUserSafeError(http.StatusForbidden, "Username or password is invalid")
	default:
		return err
	}
}
