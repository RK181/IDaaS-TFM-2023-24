package constants

type contextKey string

const (
	AUTH_USER         contextKey = "authUser"         // Clave para almacenar el usuario autenticado en el contexto
	AUTH_USER_TOKEN   string     = "authUserToken"    // Clave para almacenar el token de sesión en las cookies
	CALLBACK_URI      string     = "auth/callback"    // Clave para almacenar la URI de redirección en el contexto
	PORT              string     = ":9998"            // Puerto en el que escucha el servidor
	BASE_URL          string     = "http://localhost" // URL base del servidor
	QUERY_AUTH_REQ_ID string     = "authRequestID"    // Clave para almacenar el id de la solicitud de autenticación en el contexto
)

/*
type Config struct {
	auth_user         contextKey
	auth_user_token   string
	callback_uri      string
	port              string
	base_url          string
	query_auth_req_id string
}
*/
