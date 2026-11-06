package render

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/taviani/kde-auth/internal/domain"
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
	if strings.Contains(body, "/register") || strings.Contains(body, "Sign up") {
		t.Fatal("login without a public client must not link to register")
	}
	if !strings.Contains(body, "/forgot-password") {
		t.Fatal("login should still link to forgot-password")
	}
}

func TestLoginTemplateSignupLink(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.HTML(rec, "login.html", PageData{Title: "Sign in", RegisterURL: "/register?ticket=abc"})
	body := rec.Body.String()
	if !strings.Contains(body, `href="/register?ticket=abc"`) || !strings.Contains(body, "Sign up") {
		t.Fatalf("missing signup link: %s", body)
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
		Title:       "Open app",
		RedirectURL: template.URL("app://callback?code=abc&state=dev"),
	})
	body := rec.Body.String()
	if !strings.Contains(body, "Open app") {
		t.Fatalf("missing title: %s", body)
	}
	if !strings.Contains(body, `href="app://callback?code=abc&amp;state=dev"`) {
		t.Fatalf("missing redirect link: %s", body)
	}
}

func TestAdminClientsTemplateEditsRedirectURIs(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.HTMLData(rec, "admin_clients.html", struct {
		Title              string
		Error              string
		Success            string
		NewSecret          string
		NewClientID        string
		EditClientID       string
		EditRedirectURIs   string
		EditAndroidPackage string
		Clients            []domain.OAuthClient
	}{
		Title:              "OAuth clients",
		Error:              "redirect URI must be absolute",
		EditClientID:       "app",
		EditRedirectURIs:   "https://app.example/cb\n<script>",
		EditAndroidPackage: "com.example.<app>",
		Clients: []domain.OAuthClient{
			{
				ClientID:                "app",
				Name:                    "App",
				TokenEndpointAuthMethod: domain.TokenAuthNone,
				AccessMode:              domain.AccessModePublic,
				RedirectURIs:            []string{"https://old.example/cb"},
				AndroidPackage:          "com.old.example",
			},
			{
				ClientID:                "other",
				Name:                    "Other",
				TokenEndpointAuthMethod: domain.TokenAuthClientSecretPost,
				AccessMode:              domain.AccessModeInviteOnly,
				RedirectURIs:            []string{"https://other.example/cb", "app://cb"},
				AndroidPackage:          "com.other.example",
			},
		},
	})
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/admin/clients/redirect-uris"`) {
		t.Fatalf("missing redirect form: %s", body)
	}
	if !strings.Contains(body, "https://app.example/cb\n&lt;script&gt;") {
		t.Fatalf("draft URI was not preserved: %s", body)
	}
	if strings.Contains(body, "<script>") {
		t.Fatalf("draft was not escaped: %s", body)
	}
	if !strings.Contains(body, "https://other.example/cb\napp://cb") {
		t.Fatalf("stored URIs missing: %s", body)
	}
	if strings.Contains(body, "https://old.example/cb") {
		t.Fatalf("failed edit should show the draft, not the stored URI: %s", body)
	}
	if !strings.Contains(body, `name="android_package"`) || !strings.Contains(body, `value="com.example.&lt;app&gt;"`) {
		t.Fatalf("draft package missing: %s", body)
	}
	if strings.Contains(body, "com.old.example") {
		t.Fatalf("failed edit should show the draft package: %s", body)
	}
	if !strings.Contains(body, `value="com.other.example"`) {
		t.Fatalf("stored package missing: %s", body)
	}
}
