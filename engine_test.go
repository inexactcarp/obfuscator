package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestFixturesMatchTheJavaScriptSuite(t *testing.T) {
	eng := mustEngine(t)
	cases := []struct {
		name     string
		platform string
		counts   map[string]int
	}{
		{"ios.cfg", "ios", map[string]int{"enable": 7, "user": 3, "line": 3, "snmp": 4, "tacacsRadius": 7, "keychain": 1, "routing": 4, "ntp": 1, "crypto": 6, "wireless": 3}},
		{"nxos.cfg", "nxos", map[string]int{"user": 2, "line": 1, "snmp": 4, "tacacsRadius": 3, "keychain": 1, "routing": 3, "ntp": 1}},
		{"eos.cfg", "eos", map[string]int{"user": 3, "snmp": 4, "tacacsRadius": 3, "keychain": 1, "routing": 2, "ntp": 1, "mgmt": 1}},
	}
	for _, tc := range cases {
		input := mustRead(t, "test/fixtures/"+tc.name)
		result, err := eng.Process(input, "auto", "", nil)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if result.Platform != tc.platform {
			t.Fatalf("%s platform %s", tc.name, result.Platform)
		}
		if result.Uncertain {
			t.Fatalf("%s was uncertain", tc.name)
		}
		if strings.Contains(result.Output, "SEC_") {
			t.Fatalf("%s leaked a secret", tc.name)
		}
		lines := map[string]bool{}
		for _, line := range strings.Split(result.Output, "\n") {
			lines[line] = true
		}
		for _, line := range strings.Split(input, "\n") {
			if strings.Contains(line, "SEC_") {
				if strings.Contains(result.Output, line) {
					t.Fatalf("%s leaked line %q", tc.name, line)
				}
			} else if !lines[line] {
				t.Fatalf("%s changed a non-secret line %q", tc.name, line)
			}
		}
		sum := 0
		for id, want := range tc.counts {
			if result.Counts[id] != want {
				t.Fatalf("%s count %s = %d, want %d", tc.name, id, result.Counts[id], want)
			}
			sum += want
		}
		if got := len(regexp.MustCompile(`REDACTED_\d+`).FindAllString(result.Output, -1)); got != sum {
			t.Fatalf("%s tokens %d, want %d", tc.name, got, sum)
		}
	}
}

func TestPrefixDotAndPlaceholder(t *testing.T) {
	eng := mustEngine(t)
	input := "enable secret 0 SEC_A\nip address 10.1.4.9 255.255.255.0\n"
	ignored, err := eng.Process(input, "auto", "XXXXX", map[string]string{"10.1": "SITEA"})
	if err != nil {
		t.Fatal(err)
	}
	if ignored.AddressesRewritten != 0 || !strings.Contains(ignored.Output, "10.1.4.9") {
		t.Fatalf("undotted prefix was applied: %s", ignored.Output)
	}
	if strings.Contains(ignored.Output, "SEC_A") || !strings.Contains(ignored.Output, "XXXXX_1") {
		t.Fatalf("placeholder: %s", ignored.Output)
	}

	rewritten, err := eng.Process(input, "auto", "SECRET", map[string]string{"10.1": "x.x", "255.255": "x.x"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rewritten.Output, "x.x.4.9 x.x.255.0") || !strings.Contains(rewritten.Output, "SECRET_1") {
		t.Fatalf("rewrite: %s", rewritten.Output)
	}
	if strings.Contains(rewritten.Output, "SEC_A") || strings.Contains(rewritten.Output, "10.1.4.9") {
		t.Fatalf("secret or old prefix remained: %s", rewritten.Output)
	}
}

func TestCommandOutput(t *testing.T) {
	eng := mustEngine(t)
	input := strings.Join([]string{
		"edge-sw1#show ip route",
		"edge-sw1#enable secret 5 SEC_PROMPT",
		"O  10.1.4.9/32 [110/2] via 10.20.1.1",
		"Community name: SEC_COMM",
		"description password is not a secret",
	}, "\n")
	result, err := eng.Process(input, "auto", "", map[string]string{"10.1": "x.x", "10.20": "x.x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result.Output, "SEC_") {
		t.Fatalf("leaked: %s", result.Output)
	}
	for _, want := range []string{
		"edge-sw1#show ip route",
		"edge-sw1#enable secret 5 REDACTED_",
		"x.x.4.9/32",
		"via x.x.1.1",
		"Community name: REDACTED_",
		"description password is not a secret",
	} {
		if !strings.Contains(result.Output, want) {
			t.Fatalf("missing %q in %s", want, result.Output)
		}
	}
}

func TestPrepareText(t *testing.T) {
	text, err := prepareText([]byte{0xEF, 0xBB, 0xBF, 'a', 0, 'b', ' ', '1'})
	if err != nil || text != "ab 1" {
		t.Fatalf("got %q %v", text, err)
	}
	if _, err := prepareText([]byte{0, 0, ' ', '\n'}); err == nil {
		t.Fatal("blank file was accepted")
	}
}

func mustEngine(t *testing.T) *Engine {
	t.Helper()
	eng, err := newEngine()
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
