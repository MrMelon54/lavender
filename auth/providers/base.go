package providers

import (
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/logger"
)

var _ auth.Provider = (*InitialLogin)(nil)

type InitialLogin struct{}

func (m *InitialLogin) AccessState() auth.State { return auth.StateUnauthorized }

func (m *InitialLogin) Name() string { return "base" }

func (m *InitialLogin) RenderTemplate(ctx authContext.FormContext) error {
	type s struct {
		UserEmail string
		Redirect  string
	}

	req := ctx.Request()
	q := req.URL.Query()
	cookie, err := req.Cookie("lavender-user-memory")
	if err == nil && cookie.Valid() == nil {
		ctx.Render(s{
			UserEmail: cookie.Value,
			Redirect:  q.Get("redirect"),
		})
		return nil
	}

	ctx.Render(s{
		UserEmail: "",
		Redirect:  q.Get("redirect"),
	})
	return nil
}

func (m *InitialLogin) AttemptLogin(ctx authContext.FormContext) error {
	req := ctx.Request()
	userEmail := req.FormValue("email")
	rememberMe := req.FormValue("remember-me")
	logger.Logger.Debug("Hi", "em", userEmail, "rm", rememberMe)
	return nil
}
