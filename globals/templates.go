package globals

import (
	"html/template"
	"module/models"
	"net/http"
)

// Templates almacena las plantillas cargadas en memoria
var Templates map[string]*template.Template

// Devuelve la vista con la plantilla, información de autenticación y datos adicionales
func ReturnView(w http.ResponseWriter, r *http.Request, tmplName string, data map[string]interface{}) {
	// Añadimos la información de autenticación
	if data == nil {
		data = make(map[string]interface{})
	}
	data["AuthUser"], data["isAuth"] = (r.Context().Value(AUTH_USER).(models.User))

	tmpl := Templates[tmplName]
	tmpl.Execute(w, data)
}

// Devuelve la vista con la plantilla, información de autenticación y datos adicionales
func ReturnViewT(w http.ResponseWriter, r *http.Request, tmplName string, data map[string]interface{}) {
	// Añadimos la información de autenticación

	tmpl := Templates[tmplName]
	tmpl.Execute(w, nil)
}
