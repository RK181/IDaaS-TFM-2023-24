package webapp

import (
	"module/globals"
	"net/http"
)

type AuthController struct{}

// GetLogin redirige a la página de inicio de sesión de IDP
func (a *AuthController) GetLogin(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

// GetLogout cierra la sesión de un usuario
func (a *AuthController) GetLogout(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

// GetEmailVerification muestra el resultado de la verificación de correo
func (a *AuthController) GetEmailVerification(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

// GetRegister muestra el formulario de registro de un usuario
func (a *AuthController) GetRegister(w http.ResponseWriter, r *http.Request) {
	globals.ReturnView(w, r, "register.html", nil)
}

// PostRegister registra un nuevo usuario
func (a *AuthController) PostRegister(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}
