package providers

import (
	"context"
	"fmt"
	"github.com/1f349/cache"
	"github.com/1f349/lavender/auth"
	"github.com/1f349/lavender/auth/authContext"
	"github.com/1f349/lavender/database"
	"github.com/1f349/lavender/issuer"
	"github.com/1f349/lavender/url"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"html/template"
	"net/http"
	"time"
)

type flowStateData struct {
	loginName string
	sso       *issuer.WellKnownOIDC
	redirect  string
}

var (
	_ auth.Provider = (*OAuthLogin)(nil)
	_ auth.Button   = (*OAuthLogin)(nil)
)

type OAuthLogin struct {
	DB *database.Queries

	BaseUrl *url.URL

	flow *cache.Cache[string, flowStateData]
}

func (o OAuthLogin) Init() {
	o.flow = cache.New[string, flowStateData]()
}

func (o OAuthLogin) authUrlBase(ref string) *url.URL {
	return o.BaseUrl.Resolve("oauth", o.Name(), ref)
}

func (o OAuthLogin) AccessState() auth.State { return auth.StateUnauthorized }

func (o OAuthLogin) Name() string { return "oauth" }

func (o OAuthLogin) AttemptLogin(ctx authContext.FormContext) error {
	rCtx := ctx.Context()

	login, ok := rCtx.Value(oauthServiceLogin(0)).(*issuer.WellKnownOIDC)
	if !ok {
		return fmt.Errorf("missing issuer wellknown")
	}
	loginName := rCtx.Value("login_full").(string)
	loginUn := rCtx.Value("login_username").(string)

	// save state for use later
	state := login.Config.Namespace + ":" + uuid.NewString()
	o.flow.Set(state, flowStateData{
		loginName: loginName,
		sso:       login,
		redirect:  ctx.Request().PostFormValue("redirect"),
	}, time.Now().Add(15*time.Minute))

	// generate oauth2 config and redirect to authorize URL
	oa2conf := login.OAuth2Config
	oa2conf.RedirectURL = o.authUrlBase("callback").String()
	nextUrl := oa2conf.AuthCodeURL(state, oauth2.SetAuthURLParam("login_name", loginUn))

	return auth.RedirectError{Target: nextUrl, Code: http.StatusFound}
}

func (o OAuthLogin) OAuthCallback(rw http.ResponseWriter, req *http.Request, info func(req *http.Request, sso *issuer.WellKnownOIDC, token *oauth2.Token) (auth.UserAuth, error), cookie func(rw http.ResponseWriter, authData auth.UserAuth, loginName string) bool, redirect func(rw http.ResponseWriter, req *http.Request)) {
	flowState, ok := o.flow.Get(req.FormValue("state"))
	if !ok {
		http.Error(rw, "Invalid flow state", http.StatusBadRequest)
		return
	}
	token, err := flowState.sso.OAuth2Config.Exchange(context.Background(), req.FormValue("code"), oauth2.SetAuthURLParam("redirect_uri", o.authUrlBase("callback").String()))
	if err != nil {
		http.Error(rw, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}

	userAuth, err := info(req, flowState.sso, token)
	if err != nil {
		http.Error(rw, "Failed to update external user info", http.StatusInternalServerError)
		return
	}

	if cookie(rw, userAuth, flowState.loginName) {
		http.Error(rw, "Failed to save login cookie", http.StatusInternalServerError)
		return
	}
	if flowState.redirect != "" {
		req.Form.Set("redirect", flowState.redirect)
	}
	redirect(rw, req)
}

func (o OAuthLogin) ButtonName() string { return o.Name() }

func (o OAuthLogin) RenderButtonTemplate(ctx context.Context, req *http.Request) template.HTML {
	// o.authUrlBase("button")
	return "<div>OAuth Login Template</div>"
}

type oauthServiceLogin int

func WithWellKnown(ctx context.Context, login *issuer.WellKnownOIDC) context.Context {
	return context.WithValue(ctx, oauthServiceLogin(0), login)
}
