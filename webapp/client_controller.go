package webapp

import (
	"net/http"
)

type ClientController struct{}

// GetCreateNativeClient muestra el formulario para crear un cliente nativo
func (c *ClientController) GetCreateClient(w http.ResponseWriter, r *http.Request) {
	// TODO: Implementar la vista para crear un cliente
	panic("not implemented")
}

func (c *ClientController) PostCreateClient(w http.ResponseWriter, r *http.Request) {
	// Parse form values
	/*userID, err := strconv.Atoi(r.FormValue("user_id"))
	if err != nil {
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	clientName := r.FormValue("client_name")
	secret := r.FormValue("secret")
	redirectURIs := strings.Split(r.FormValue("redirect_uris"), ",")

	// Create web client
	client, err := models.CreateWebClient(userID, clientName, secret, redirectURIs)
	if err != nil {
		http.Error(w, "Error creating web client", http.StatusInternalServerError)
		return
	}*/

	// TODO: Implementar la creación de un cliente web
	panic("not implemented")
}

// GetUpdateClient muestra el formulario para actualizar un cliente
func (c *ClientController) GetUpdateClient(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

// PostUpdateClient actualiza un cliente
func (c *ClientController) PostUpdateClient(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

// DeleteClient elimina un cliente
func (c *ClientController) DeleteClient(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}

// GetAllClients muestra todos los clientes de un usuario
func (c *ClientController) GetAllClients(w http.ResponseWriter, r *http.Request) {
	panic("not implemented")
}
