package render

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterTemplateIncludesTicket(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.HTML(rec, "register.html", PageData{Title: "Register", Ticket: "abc"})
	if rec.Code != 200 {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="ticket"`) || !strings.Contains(body, "abc") {
		t.Fatalf("missing ticket field: %s", body)
	}
}

func TestLoginTemplateHasNoRegisterLink(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.HTML(rec, "login.html", PageData{Title: "Sign in"})
	body := rec.Body.String()
	if strings.Contains(body, "/register") {
		t.Fatal("login must not link to register")
	}
	if !strings.Contains(body, "/forgot-password") {
		t.Fatal("login should still link to forgot-password")
	}
}

func TestAuthorizeAppOpenTemplate(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.HTMLData(rec, "authorize_app_open.html", struct {
		Title       string
		RedirectURL template.URL
	}{
		Title:       "Ouvrir l'application",
		RedirectURL: template.URL("app://callback?code=abc&state=dev"),
	})
	body := rec.Body.String()
	if !strings.Contains(body, "Ouvrir l") {
		t.Fatalf("missing title: %s", body)
	}
	if !strings.Contains(body, `href="app://callback?code=abc&amp;state=dev"`) {
		t.Fatalf("missing redirect link: %s", body)
	}
}
