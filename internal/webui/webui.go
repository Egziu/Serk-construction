// Package webui serves the SERK operations console: a static, dependency-free
// single-page application embedded in the binary. It holds no business
// logic and no authority: every action is an API call that the kernel and
// PostgreSQL re-authorize. What the console hides or shows by permission is
// convenience, never a control.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed static
var files embed.FS

// CSP for the console: same-origin scripts, styles and API calls only; no
// inline script or style, no framing, no plugins, no form posts elsewhere.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

var types = map[string]string{
	".html":  "text/html; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".svg":   "image/svg+xml",
	".woff2": "font/woff2",
	".txt":   "text/plain; charset=utf-8",
}

// Handler serves /console/ and its assets. Unknown paths fall back to the
// application shell (client-side routes use the URL fragment, so this only
// matters for bookmarks of /console itself).
func Handler() http.Handler {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err) // embedded at build time; cannot fail at run time
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/console/")
		if name == "" || strings.Contains(name, "..") {
			name = "index.html"
		}
		b, err := fs.ReadFile(sub, name)
		if err != nil {
			name = "index.html"
			b, _ = fs.ReadFile(sub, name)
		}
		h := w.Header()
		h.Set("Content-Security-Policy", CSP)
		h.Set("Content-Type", types[path.Ext(name)])
		h.Set("Cache-Control", "no-cache")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	})
}
