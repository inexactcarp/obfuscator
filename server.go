package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed index.html styles.css src
var content embed.FS

// handler serves the obfuscator page. It never reads a request body, so a
// pasted config cannot be uploaded here. Redaction runs in the browser.
func handler() http.Handler {
	files, err := fs.Sub(content, ".")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(files))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "This program only serves the page.", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fileServer.ServeHTTP(w, r)
	})
}

func loopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || host == "localhost" {
		return true
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.Trim(host, "[]")
	}
	return host == "127.0.0.1" || host == "::1"
}
