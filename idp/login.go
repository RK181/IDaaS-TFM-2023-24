package idp

import (
	"context"
	"fmt"
	"module/config/constants"
	"module/config/templates"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/zitadel/oidc/v3/pkg/op"
)

type login struct {
	authenticate authenticate
	router       chi.Router
	callback     func(context.Context, string) string
}

func NewLogin(authenticate authenticate, callback func(context.Context, string) string, issuerInterceptor *op.IssuerInterceptor) *login {
	l := &login{
		authenticate: authenticate,
		callback:     callback,
	}
	l.createRouter(issuerInterceptor)
	return l
}

func (l *login) createRouter(issuerInterceptor *op.IssuerInterceptor) {
	l.router = chi.NewRouter()
	l.router.Get("/username", l.loginHandler)
	l.router.Post("/username", issuerInterceptor.HandlerFunc(l.checkLoginHandler))
}

type authenticate interface {
	CheckUsernamePassword(username, password, id string) error
	//GetScopes(id string) []string
}

func (l *login) loginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse form:%s", err), http.StatusInternalServerError)
		return
	}
	// the oidc package will pass the id of the auth request as query parameter
	// we will use this id through the login process and therefore pass it to the login page
	renderLogin(w, r, r.FormValue(constants.QUERY_AUTH_REQ_ID), nil, l)
}

func renderLogin(w http.ResponseWriter, r *http.Request, id string, err error, l *login) {

	data := map[string]interface{}{
		"Error": err,
		"ID":    id,
	}

	templates.ReturnView(w, r, "login.html", data)
}

func (l *login) checkLoginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, fmt.Sprintf("cannot parse form:%s", err), http.StatusInternalServerError)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	id := r.FormValue("id")
	err = l.authenticate.CheckUsernamePassword(username, password, id)
	if err != nil {
		renderLogin(w, r, id, err, l)
		return
	}
	http.Redirect(w, r, l.callback(r.Context(), id), http.StatusFound)
}
