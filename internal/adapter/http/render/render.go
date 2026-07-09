package render

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templatesFS embed.FS

type Renderer struct {
	templates *template.Template
}

func New() (*Renderer, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Renderer{templates: tmpl}, nil
}

type PageData struct {
	Title           string
	Error           string
	Success         string
	Email           string
	Next            string
	TurnstileSiteKey string
}

func (r *Renderer) HTML(w http.ResponseWriter, name string, data PageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := r.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}
