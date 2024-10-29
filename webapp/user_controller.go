package webapp

import (
	"module/config/templates"
	"net/http"
)

type UserController struct{}

// GetProfile muestra el perfil de un usuario
func (u *UserController) GetProfile(w http.ResponseWriter, r *http.Request) {

	templates.ReturnView(w, r, "profile.html", nil)
}

// GetUpateUser muestra el formulario para actualizar un usuario
func (u *UserController) GetUpdateUser(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

// PostUpdateUser actualiza un usuario
func (u *UserController) PostUpdateUser(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

// DeleteUser elimina un usuario
func (u *UserController) DeleteUser(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}
