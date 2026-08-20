package render

import (
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
