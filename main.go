package main

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"log/slog"
	"module/globals"
	"module/globals/constants"
	"module/idp"
	"module/models"
	"module/webapp"
	"net/http"
	"os"
)

// Configuración de las rutas de las plantillas
const (
	layoutsDir   = "views/layouts"
	templatesDir = "views"
	extension    = "/*.html"
)

// Incrustamos las plantillas en el binario
var (
	//go:embed views/* views/layouts/*
	files embed.FS
)

// LoadTemplates carga las plantillas en memoria
func LoadTemplates() error {
	if globals.Templates == nil {
		globals.Templates = make(map[string]*template.Template)
	}
	tmplFiles, err := fs.ReadDir(files, templatesDir)
	if err != nil {
		return err
	}
	for _, tmpl := range tmplFiles {
		if tmpl.IsDir() {
			continue
		}
		pt, err := template.ParseFS(files, templatesDir+"/"+tmpl.Name(), layoutsDir+extension)
		if err != nil {
			return err
		}
		globals.Templates[tmpl.Name()] = pt
	}
	return nil
}

/*func faviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "public/favicon.ico")
}*/

func main() {
	//runtime.GOMAXPROCS(runtime.NumCPU())
	models.InitDatabase()
	// Cargamos las plantillas
	err := LoadTemplates()
	if err != nil {
		log.Fatal(err)
	}
	issuer := fmt.Sprintf("http://localhost%s/", constants.PORT)
	storage := idp.NewStorage()

	logger := slog.New(
		slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			AddSource: true,
			Level:     slog.LevelDebug,
		}),
	)
	router := idp.SetupServer(issuer, storage, logger, false)

	// Creamos un servidor
	server := &http.Server{
		Addr:    constants.PORT, // Puerto en el que escucha el servidor
		Handler: router,         // Registramos los middlewares
	}

	// Mostramos un mensaje en consola
	log.Printf("Server is listening at %s ...\n", constants.BASE_URL+constants.PORT)
	log.Println("Press Ctrl + C to stop the server")

	// Iniciamos el servidor
	log.Fatal(server.ListenAndServe())

}

func loadRouter() *http.ServeMux {
	// Creamos los routers
	router := http.NewServeMux()

	// Obtenemos el controlador de usuario
	userController := &webapp.UserController{}
	authController := &webapp.AuthController{}
	loginController := &idp.LoginController{}
	// Obtenemos el controlador de publicaciones
	//clientController := &webapp.ClientController{}

	// -----------------------------------------------
	// RUTAS PÚBLICAS
	// -----------------------------------------------
	//router.HandleFunc("GET /favicon.ico", faviconHandler)
	router.HandleFunc("GET /about", func(w http.ResponseWriter, r *http.Request) {
		globals.ReturnView(w, r, "about.html", nil)
	})
	router.HandleFunc("GET /client/create", func(w http.ResponseWriter, r *http.Request) {
		globals.ReturnView(w, r, "clientCreate.html", nil)
	})
	router.HandleFunc("GET /twofa", func(w http.ResponseWriter, r *http.Request) {
		globals.ReturnView(w, r, "twoFA.html", nil)
	})
	router.HandleFunc("GET /concent", func(w http.ResponseWriter, r *http.Request) {
		globals.ReturnView(w, r, "concent.html", nil)
	})
	router.HandleFunc("GET /verify", func(w http.ResponseWriter, r *http.Request) {
		globals.ReturnView(w, r, "verify.html", nil)
	})
	// -----------------------------------------------
	// RUTAS QUE REQUIEREN INFORMACIÓN DE AUTENTICACIÓN
	// -----------------------------------------------

	router.HandleFunc("GET /register", authController.GetRegister)
	router.HandleFunc("GET /login", loginController.GetLogin)

	router.HandleFunc("GET /profile", userController.GetProfile)

	//router.HandleFunc("GET /profile/update", userController.GetUpdateUser)

	//router.HandleFunc("GET /auth/email", authController.GetEmailVerification)
	//router.HandleFunc("GET /

	return router
}
