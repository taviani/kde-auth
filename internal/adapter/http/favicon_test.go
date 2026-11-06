package httpadapter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/taviani/kde-auth/internal/platform/config"
)

func TestFavicon(t *testing.T) {
	router := NewRouter(config.Config{}, Handlers{})
	for _, path := range []string{"/favicon.ico", "/favicon.png"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status %d", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "image/png" {
			t.Fatalf("%s content-type %q", path, got)
		}
		if !strings.HasPrefix(rec.Body.String(), "\x89PNG") {
			t.Fatalf("%s is not a PNG", path)
		}
	}
}
