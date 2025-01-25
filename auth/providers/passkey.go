package providers

import (
	"context"
	"github.com/1f349/lavender/auth"
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

func (p *PasskeyLogin) RenderButtonTemplate(ctx context.Context, req *http.Request) template.HTML {
	return "<div>Passkey Button</div>"
}
