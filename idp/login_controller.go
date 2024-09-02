package idp

import (
	"module/globals"
	"net/http"
)

type LoginController struct{}

// GetLogin muestra el formulario de inicio de sesión
func (a *LoginController) GetLogin(w http.ResponseWriter, r *http.Request) {
	globals.ReturnView(w, r, "login.html", nil)
}
