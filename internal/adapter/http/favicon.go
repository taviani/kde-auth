package httpadapter

import (
	_ "embed"
	"net/http"
)

//go:embed favicon.png
var faviconPNG []byte

func favicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=604800")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(faviconPNG)
}
