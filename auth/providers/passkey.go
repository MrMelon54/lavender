package providers

import (
	"context"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/database"
	"net/http"
)

type passkeyLoginDB interface {
	auth.lookupUserDB
}

var _ auth.Provider = (*PasskeyLogin)(nil)

type PasskeyLogin struct {
	DB passkeyLoginDB
}

func (p *PasskeyLogin) Factor() auth.State { return FactorBasic }

func (p *PasskeyLogin) Name() string { return "passkey" }

func (p *PasskeyLogin) RenderData(ctx context.Context, req *http.Request, user *database.User, data map[string]any) error {
	if user == nil || user.Subject == "" {
		return ErrRequiresPreviousFactor
	}
	if user.OtpSecret == "" {
		return auth.ErrUserDoesNotSupportFactor
	}

	//TODO implement me
	panic("implement me")
}

var passkeyShortcut = true

func init() {
	passkeyShortcut = true
}

func (p *PasskeyLogin) AttemptLogin(ctx context.Context, req *http.Request, user *database.User) error {
	if user.Subject == "" && !passkeyShortcut {
		return ErrRequiresPreviousFactor
	}

	//TODO implement me
	panic("implement me")
}
