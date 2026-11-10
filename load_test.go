package main

import (
	"strings"
	"testing"
)

func TestLoadingANewFileRebuildsFileState(t *testing.T) {
	u := newUI(mustEngine(t))
	u.placeholder.selected = 1
	u.scrollLock = true
	u.loadText("hostname old\nip address 10.1.4.9 255.255.255.0\nenable secret 0 SEC_OLD\n")

	if !strings.Contains(u.output.Text(), "SECRET_1") {
		t.Fatalf("first file was not redacted: %s", u.output.Text())
	}
	setPrefix(t, u, "10.1", "x.x")
	u.platform.selected = 2
	u.prefixAll.SetText("z.z")
	u.applied = ""
	u.obfuscate()
	if !strings.Contains(u.output.Text(), "x.x.4.9") {
		t.Fatalf("prefix edit was not applied: %s", u.output.Text())
	}

	// Same prefixes as the open file, so a stale signature must not win.
	u.loadText("hostname new\nip address 10.1.8.8 255.255.255.0\nenable secret 0 SEC_NEW\n")

	if got := prefixValue(t, u, "10.1"); got != "10.1" {
		t.Fatalf("old prefix edit stuck: %q", got)
	}
	if strings.Contains(u.output.Text(), "x.x.4.9") || strings.Contains(u.output.Text(), "10.1.4.9") {
		t.Fatalf("old address stayed in the output: %s", u.output.Text())
	}
	if !strings.Contains(u.output.Text(), "10.1.8.8") {
		t.Fatalf("new address missing: %s", u.output.Text())
	}
	if strings.Contains(u.output.Text(), "SEC_NEW") || strings.Contains(u.output.Text(), "SEC_OLD") {
		t.Fatalf("secret from one of the files leaked: %s", u.output.Text())
	}
	if !strings.Contains(u.output.Text(), "SECRET_1") {
		t.Fatalf("placeholder preference was dropped: %s", u.output.Text())
	}
	if u.platform.selected != 0 {
		t.Fatalf("platform override stuck at %d", u.platform.selected)
	}
	if u.prefixAll.Text() != "x.x" {
		t.Fatalf("set-all value stuck at %q", u.prefixAll.Text())
	}
	if !u.scrollLock {
		t.Fatal("scroll lock is a window preference and was cleared")
	}
	if !strings.Contains(u.summary, "secret field") {
		t.Fatalf("summary was not rebuilt: %s", u.summary)
	}
	if strings.Contains(u.input.Text(), "hostname old") || !strings.Contains(u.input.Text(), "hostname new") {
		t.Fatalf("input was not replaced: %s", u.input.Text())
	}
}

func setPrefix(t *testing.T, u *ui, prefix, value string) {
	t.Helper()
	for i := range u.rows {
		if u.rows[i].prefix == prefix {
			u.rows[i].edit.SetText(value)
			return
		}
	}
	t.Fatalf("prefix %s not found", prefix)
}

func prefixValue(t *testing.T, u *ui, prefix string) string {
	t.Helper()
	for i := range u.rows {
		if u.rows[i].prefix == prefix {
			return u.rows[i].edit.Text()
		}
	}
	t.Fatalf("prefix %s not found", prefix)
	return ""
}
