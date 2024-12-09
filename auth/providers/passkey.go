package providers

import (
	"context"
	"fmt"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/database"
	"html/template"
	"net/http"
)

type passkeyLoginDB interface {
	auth.LookupUserDB
}

var _ auth.Provider = (*PasskeyLogin)(nil)

type PasskeyLogin struct {
	DB passkeyLoginDB
}

func (p *PasskeyLogin) AccessState() auth.State { return auth.StateUnauthorized }

func (p *PasskeyLogin) Name() string { return "passkey" }

func (p *PasskeyLogin) RenderTemplate(ctx context.Context, req *http.Request, user *database.User) (template.HTML, error) {
	if user == nil || user.Subject == "" {
		return "", fmt.Errorf("requires previous factor")
	}
	if user.OtpSecret == "" {
		return "", fmt.Errorf("user does not support factor")
	}

	panic("implement me")
}

var passkeyShortcut = true

func init() {
	passkeyShortcut = true
}

func (p *PasskeyLogin) AttemptLogin(ctx context.Context, req *http.Request, user *database.User) error {
	if user.Subject == "" && !passkeyShortcut {
		return fmt.Errorf("requires previous factor")
	}

	//TODO implement me
	panic("implement me")
}
