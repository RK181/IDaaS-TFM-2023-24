package globals

type contextKey string

const (
	AUTH_USER       contextKey = "authUser"         // Clave para almacenar el usuario autenticado en el contexto
	AUTH_USER_TOKEN string     = "authUserToken"    // Clave para almacenar el token de sesión en las cookies
	CALLBACK_URI    string     = "auth/callback"    // Clave para almacenar la URI de redirección en el contexto
	PORT            string     = ":9090"            // Puerto en el que escucha el servidor
	BASE_URL        string     = "http://localhost" // URL base del servidor
)
