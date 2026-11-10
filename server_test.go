package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPageIsServedWithoutAcceptingConfigs(t *testing.T) {
	srv := httptest.NewServer(handler())
	defer srv.Close()

	page := get(t, srv.URL+"/")
	if !strings.Contains(page, "Config Obfuscator") || !strings.Contains(page, "src/app.js") {
		t.Fatalf("index page is missing the app: %s", page[:min(200, len(page))])
	}

	script := get(t, srv.URL+"/src/redact.js")
	if !strings.Contains(script, "export function redactConfig") {
		t.Fatal("redactor script was not embedded")
	}
	style := get(t, srv.URL+"/styles.css")
	if !strings.Contains(style, "prefix-row") {
		t.Fatal("stylesheet was not embedded")
	}

	res, err := http.Get(srv.URL + "/test/fixtures/ios.cfg")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("fixture leaked from the executable: %d", res.StatusCode)
	}

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader("enable secret 0 SECRET_SHOULD_NOT_ECHO"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status %d", resp.StatusCode)
	}
	if strings.Contains(string(body), "SECRET_SHOULD_NOT_ECHO") {
		t.Fatal("server echoed a posted secret")
	}
}

func TestLoopbackOnly(t *testing.T) {
	if !loopbackHost("127.0.0.1") || !loopbackHost("localhost") || !loopbackHost("::1") {
		t.Fatal("loopback hosts were rejected")
	}
	if loopbackHost("0.0.0.0") || loopbackHost("10.1.1.1") {
		t.Fatal("non-loopback host was accepted")
	}
}

func get(t *testing.T, url string) string {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d", url, res.StatusCode)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
