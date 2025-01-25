package providers

import (
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/web"
)

var _ auth.Provider = (*MemoryLogin)(nil)

type MemoryLogin struct{}

func (m *MemoryLogin) AccessState() auth.State { return auth.StateUnauthorized }

func (m *MemoryLogin) Name() string { return "memory" }

func (m *MemoryLogin) RenderTemplate(ctx authContext.TemplateContext) error {
	cookie, err := ctx.Request().Cookie("lavender-user-memory")
	if err == nil && cookie.Valid() == nil {
		ctx.Render(struct {
			ServiceName string
			LoginName   string
			Redirect    string
		}{
			ServiceName: ,
		})
	}
}

func (m *MemoryLogin) AttemptLogin(ctx authContext.TemplateContext) error {
	//TODO implement me
	panic("implement me")
}
