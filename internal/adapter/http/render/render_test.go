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
