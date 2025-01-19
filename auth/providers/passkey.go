package providers

import (
	"context"
	"fmt"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"html/template"
	"net/http"
)

type passkeyLoginDB interface {
	auth.LookupUserDB
}

var (
	_ auth.Provider = (*PasskeyLogin)(nil)
	_ auth.Button   = (*PasskeyLogin)(nil)
)

type PasskeyLogin struct {
	DB passkeyLoginDB
}

func (p *PasskeyLogin) AccessState() auth.State { return auth.StateUnauthorized }

func (p *PasskeyLogin) Name() string { return "passkey" }

func (p *PasskeyLogin) RenderTemplate(ctx authContext.TemplateContext) error {
	user := ctx.User()
	if user == nil || user.Subject == "" {
		return fmt.Errorf("requires previous factor")
	}
	if user.OtpSecret == "" {
		return fmt.Errorf("user does not support factor")
	}

	panic("implement me")
}

var passkeyShortcut = true

func init() {
	passkeyShortcut = true
}

func (p *PasskeyLogin) AttemptLogin(ctx authContext.TemplateContext) error {
	user := ctx.User()
	if user.Subject == "" && !passkeyShortcut {
		return fmt.Errorf("requires previous factor")
	}

	//TODO implement me
	panic("implement me")
}

func (p *PasskeyLogin) ButtonName() string {
	return "Login with Passkey"
}

func (p *PasskeyLogin) RenderButtonTemplate(ctx context.Context, req *http.Request) template.HTML {
	return "<div>Passkey Button</div>"
}
