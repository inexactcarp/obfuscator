package main

import (
	"embed"
	"encoding/json"
	"strings"
	"sync"

	"github.com/dop251/goja"
)

//go:embed src/detect.js src/prefixes.js src/redact.js src/process.js
var engineFiles embed.FS

// Result is the obfuscated text and counts. It never includes the secret map.
type Result struct {
	Output             string
	Counts             map[string]int
	Categories         []Category
	Platform           string
	PlatformLabel      string
	Prefixes           []string
	AddressesRewritten int
	Uncertain          bool
}

// Category is one redaction counter shown in the summary.
type Category struct {
	ID    string
	Label string
}

type jsResult struct {
	Output             string         `json:"output"`
	Counts             map[string]int `json:"counts"`
	Platform           string         `json:"platform"`
	Prefixes           []string       `json:"prefixes"`
	AddressesRewritten int            `json:"addressesRewritten"`
	Uncertain          bool           `json:"uncertain"`
	Categories         []struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	} `json:"categories"`
	Labels map[string]string `json:"labels"`
}

// Engine runs the same JavaScript sanitizer the tests cover.
type Engine struct {
	mu   sync.Mutex
	vm   *goja.Runtime
	run  goja.Callable
	scan goja.Callable
}

func newEngine() (*Engine, error) {
	src, err := bundleEngine()
	if err != nil {
		return nil, err
	}
	prog, err := goja.Compile("engine.js", src, false)
	if err != nil {
		return nil, err
	}
	vm := goja.New()
	if _, err := vm.RunProgram(prog); err != nil {
		return nil, err
	}
	api := vm.Get("__api").ToObject(vm)
	run, ok := goja.AssertFunction(api.Get("run"))
	if !ok {
		return nil, errString("sanitizer entry point is missing")
	}
	scan, ok := goja.AssertFunction(api.Get("scan"))
	if !ok {
		return nil, errString("prefix scan entry point is missing")
	}
	return &Engine{vm: vm, run: run, scan: scan}, nil
}

func bundleEngine() (string, error) {
	names := []string{"src/detect.js", "src/prefixes.js", "src/redact.js", "src/process.js"}
	var b strings.Builder
	for _, name := range names {
		raw, err := engineFiles.ReadFile(name)
		if err != nil {
			return "", err
		}
		b.WriteString(stripModule(string(raw)))
		b.WriteByte('\n')
	}
	b.WriteString(`var __api = {
  run: function (text, override, replacementsJSON, placeholder) {
    var replacements = {};
    if (replacementsJSON) replacements = JSON.parse(replacementsJSON);
    var result = processConfig(text, override, replacements, { placeholder: placeholder });
    return JSON.stringify({
      output: result.output,
      counts: result.counts,
      platform: result.platform,
      prefixes: result.prefixes,
      addressesRewritten: result.addressesRewritten,
      uncertain: result.uncertain,
      categories: CATEGORIES,
      labels: PLATFORM_LABELS
    });
  },
  scan: function (text) {
    return JSON.stringify(scanPrefixes(text));
  }
};
`)
	return b.String(), nil
}

func stripModule(src string) string {
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trim, "import "):
			lines[i] = ""
		case strings.HasPrefix(trim, "export {"):
			lines[i] = ""
		case strings.HasPrefix(trim, "export "):
			idx := strings.Index(line, "export ")
			lines[i] = line[:idx] + line[idx+len("export "):]
		}
	}
	return strings.Join(lines, "\n")
}

// Process rewrites prefixes and redacts secrets. replacements may be nil.
func (e *Engine) Process(text, override, placeholder string, replacements map[string]string) (Result, error) {
	if replacements == nil {
		replacements = map[string]string{}
	}
	encoded, err := json.Marshal(replacements)
	if err != nil {
		return Result{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	value, err := e.run(goja.Undefined(),
		e.vm.ToValue(text),
		e.vm.ToValue(override),
		e.vm.ToValue(string(encoded)),
		e.vm.ToValue(placeholder),
	)
	if err != nil {
		return Result{}, err
	}
	raw, ok := value.Export().(string)
	if !ok {
		return Result{}, errString("sanitizer did not return a result")
	}
	var parsed jsResult
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return Result{}, err
	}
	categories := make([]Category, len(parsed.Categories))
	for i, category := range parsed.Categories {
		categories[i] = Category{ID: category.ID, Label: category.Label}
	}
	if parsed.Counts == nil {
		parsed.Counts = map[string]int{}
	}
	if parsed.Prefixes == nil {
		parsed.Prefixes = []string{}
	}
	return Result{
		Output:             parsed.Output,
		Counts:             parsed.Counts,
		Categories:         categories,
		Platform:           parsed.Platform,
		PlatformLabel:      parsed.Labels[parsed.Platform],
		Prefixes:           parsed.Prefixes,
		AddressesRewritten: parsed.AddressesRewritten,
		Uncertain:          parsed.Uncertain,
	}, nil
}

// Scan returns the unique IPv4 prefixes in first-seen numeric order.
func (e *Engine) Scan(text string) ([]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	value, err := e.scan(goja.Undefined(), e.vm.ToValue(text))
	if err != nil {
		return nil, err
	}
	raw, ok := value.Export().(string)
	if !ok {
		return nil, errString("prefix scan did not return a result")
	}
	var prefixes []string
	if err := json.Unmarshal([]byte(raw), &prefixes); err != nil {
		return nil, err
	}
	if prefixes == nil {
		prefixes = []string{}
	}
	return prefixes, nil
}

type errString string

func (e errString) Error() string { return string(e) }
