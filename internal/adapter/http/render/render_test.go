package render

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterTemplate(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.HTML(rec, "register.html", PageData{Title: "Register"})
	if rec.Code != 200 {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Create account") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestHomeTemplate(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.HTMLData(rec, "home.html", nil)
	if rec.Code != 200 {
		t.Fatalf("status %d body %q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "in girum imus nocte et consumimur igni") {
		t.Fatalf("unexpected body: %s", body)
	}
	if strings.Contains(body, "/login") {
		t.Fatal("home page must not link to login")
	}
}
