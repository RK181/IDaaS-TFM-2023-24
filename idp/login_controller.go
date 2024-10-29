package idp

import (
	"module/config/templates"
	"net/http"
)

type LoginController struct{}

// GetLogin muestra el formulario de inicio de sesión
func (a *LoginController) GetLogin(w http.ResponseWriter, r *http.Request) {
	templates.ReturnView(w, r, "login.html", nil)
}
