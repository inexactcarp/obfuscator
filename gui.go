package main

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"strings"

	"gioui.org/app"
	"gioui.org/font/gofont"
	"gioui.org/io/clipboard"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"gioui.org/x/explorer"
)

const maxFileBytes = 2 * 1024 * 1024

const emptySummary = "No results yet. Counts show how many fields were replaced. Values are not listed."

type prefixRow struct {
	prefix string
	edit   widget.Editor
}

type chooser struct {
	title    string
	keys     []string
	names    []string
	selected int
	open     bool
	btn      widget.Clickable
	items    []widget.Clickable
}

func newChooser(title string, keys, names []string) chooser {
	return chooser{
		title: title,
		keys:  keys,
		names: names,
		items: make([]widget.Clickable, len(keys)),
	}
}

func (c *chooser) key() string {
	if c.selected < 0 || c.selected >= len(c.keys) {
		return ""
	}
	return c.keys[c.selected]
}

func (c *chooser) changed(gtx layout.Context) bool {
	changed := false
	if c.btn.Clicked(gtx) {
		c.open = !c.open
	}
	for i := range c.items {
		if !c.items[i].Clicked(gtx) {
			continue
		}
		if c.selected != i {
			c.selected = i
			changed = true
		}
		c.open = false
	}
	return changed
}

type ioResult struct {
	text  string
	saved bool
	err   error
}

type ui struct {
	eng  *Engine
	win  *app.Window
	expl *explorer.Explorer
	th   *material.Theme
	ops  op.Ops

	platform    chooser
	placeholder chooser
	custom      widget.Editor
	customSeen  string

	prefixAll widget.Editor
	rows      []prefixRow
	prefixSig string
	applied   string
	list      layout.List

	input     widget.Editor
	output    widget.Editor
	inputSeen string
	hasOutput bool

	openBtn      widget.Clickable
	obfuscateBtn widget.Clickable
	clearBtn     widget.Clickable
	setAllBtn    widget.Clickable
	copyBtn      widget.Clickable
	saveBtn      widget.Clickable

	status     string
	statusKind string
	summary    string
	busy       bool
	ioCh       chan ioResult
}

func newUI(eng *Engine) *ui {
	th := material.NewTheme()
	th.Shaper = text.NewShaper(text.NoSystemFonts(), text.WithCollection(gofont.Collection()))
	th.Face = "Go"
	th.Palette = material.Palette{
		Fg:         rgb(0x1c2430),
		Bg:         rgb(0xf3f6fb),
		ContrastBg: rgb(0x0f766e),
		ContrastFg: rgb(0xffffff),
	}
	u := &ui{
		eng: eng,
		th:  th,
		platform: newChooser("Platform",
			[]string{"auto", "ios", "nxos", "eos"},
			[]string{"Auto", "Cisco IOS / IOS-XE", "Cisco NX-OS", "Arista EOS"},
		),
		placeholder: newChooser("Placeholder",
			[]string{"REDACTED", "SECRET", "XXXXX", "********", "custom"},
			[]string{"REDACTED_1", "SECRET_1", "XXXXX_1", "********_1", "Custom"},
		),
		status:  "Paste a configuration or choose a file, then obfuscate.",
		summary: emptySummary,
		ioCh:    make(chan ioResult, 1),
	}
	u.custom.SingleLine = true
	u.custom.SetText("REDACTED")
	u.customSeen = "REDACTED"
	u.prefixAll.SingleLine = true
	u.prefixAll.SetText("x.x")
	u.input.WrapPolicy = text.WrapWords
	u.output.WrapPolicy = text.WrapWords
	u.output.ReadOnly = true
	u.list.Axis = layout.Vertical
	return u
}

func (u *ui) run(w *app.Window) error {
	u.win = w
	u.expl = explorer.NewExplorer(w)
	for {
		ev := w.Event()
		u.expl.ListenEvents(ev)
		switch e := ev.(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&u.ops, e)
			u.frame(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

func (u *ui) frame(gtx layout.Context) {
	u.pollIO()
	u.noteInput()
	if u.platform.changed(gtx) && u.hasOutput {
		u.obfuscate()
	}
	if u.placeholder.changed(gtx) && u.hasOutput {
		u.obfuscate()
	}
	if u.placeholder.key() == "custom" && u.custom.Text() != u.customSeen {
		u.customSeen = u.custom.Text()
		if u.hasOutput {
			u.obfuscate()
		}
	}
	if u.openBtn.Clicked(gtx) && !u.busy {
		u.chooseFile()
	}
	if u.obfuscateBtn.Clicked(gtx) {
		u.obfuscate()
	}
	if u.clearBtn.Clicked(gtx) {
		u.clear()
	}
	if u.setAllBtn.Clicked(gtx) {
		u.setAll()
	}
	if u.copyBtn.Clicked(gtx) && u.output.Len() > 0 {
		gtx.Execute(clipboard.WriteCmd{
			Type: "application/text",
			Data: io.NopCloser(strings.NewReader(u.output.Text())),
		})
		u.setStatus("Copied the obfuscated config.", "ok")
	}
	if u.saveBtn.Clicked(gtx) && u.output.Len() > 0 && !u.busy {
		u.saveOutput(u.output.Text())
	}
	u.notePrefixes()
	u.draw(gtx)
}

func (u *ui) draw(gtx layout.Context) {
	paint.Fill(gtx.Ops, u.th.Palette.Bg)
	layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(material.H5(u.th, "Config Obfuscator").Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						l := material.Body2(u.th, "Redacts secrets in Cisco IOS, IOS-XE, NX-OS, and Arista EOS configs. The text stays in this window. Nothing is uploaded or saved.")
						l.Color = rgb(0x526072)
						return l.Layout(gtx)
					}),
				)
			}),
			layout.Rigid(u.gap(10)),
			layout.Rigid(u.controls),
			layout.Rigid(u.gap(8)),
			layout.Rigid(u.statusLine),
			layout.Rigid(u.gap(8)),
			layout.Rigid(u.prefixSection),
			layout.Rigid(u.gap(8)),
			layout.Flexed(1, u.editors),
			layout.Rigid(u.gap(8)),
			layout.Rigid(u.summarySection),
		)
	})
}

func (u *ui) gap(dp unit.Dp) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return layout.Spacer{Height: dp}.Layout(gtx)
	}
}

func (u *ui) controls(gtx layout.Context) layout.Dimensions {
	return u.card(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Start}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return u.chooserLayout(gtx, &u.platform, 230)
					}),
					layout.Rigid(u.hspace(8)),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return u.chooserLayout(gtx, &u.placeholder, 180)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						if u.placeholder.key() != "custom" {
							return layout.Dimensions{}
						}
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.End}.Layout(gtx,
							layout.Rigid(u.hspace(8)),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return u.labeledEditor(gtx, "Custom placeholder", &u.custom, 160)
							}),
						)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return layout.Dimensions{Size: image.Pt(gtx.Constraints.Max.X, 0)}
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return u.button(gtx, &u.openBtn, "Open file", !u.busy, false)
					}),
					layout.Rigid(u.hspace(8)),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return u.button(gtx, &u.obfuscateBtn, "Obfuscate", true, true)
					}),
					layout.Rigid(u.hspace(8)),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return u.button(gtx, &u.clearBtn, "Clear", true, false)
					}),
				)
			}),
		)
	})
}

func (u *ui) chooserLayout(gtx layout.Context, c *chooser, width unit.Dp) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Dp(width)
			if gtx.Constraints.Max.X < gtx.Constraints.Min.X {
				gtx.Constraints.Min.X = gtx.Constraints.Max.X
			}
			label := c.title + ": " + c.names[c.selected]
			return u.button(gtx, &c.btn, label, true, false)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if !c.open {
				return layout.Dimensions{}
			}
			var kids []layout.FlexChild
			for i := range c.items {
				i := i
				kids = append(kids, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					gtx.Constraints.Min.X = gtx.Dp(width)
					if gtx.Constraints.Max.X < gtx.Constraints.Min.X {
						gtx.Constraints.Min.X = gtx.Constraints.Max.X
					}
					return u.button(gtx, &c.items[i], c.names[i], true, c.selected == i)
				}))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
		}),
	)
}

func (u *ui) prefixSection(gtx layout.Context) layout.Dimensions {
	return u.card(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(material.H6(u.th, "IPv4 prefixes").Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body2(u.th, "Set all of them at once, or edit a row. A replacement must contain a dot, such as x.x. Leave a row unchanged to keep that prefix. The last two octets stay.")
				l.Color = rgb(0x526072)
				return l.Layout(gtx)
			}),
			layout.Rigid(u.gap(8)),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.End}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return u.labeledEditor(gtx, "Every prefix", &u.prefixAll, 120)
					}),
					layout.Rigid(u.hspace(8)),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return u.button(gtx, &u.setAllBtn, "Set all", true, true)
					}),
				)
			}),
			layout.Rigid(u.gap(6)),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if len(u.rows) == 0 {
					l := material.Body2(u.th, "No IPv4 addresses in the text yet.")
					l.Color = rgb(0x526072)
					return l.Layout(gtx)
				}
				height := gtx.Dp(unit.Dp(28))*len(u.rows) + gtx.Dp(unit.Dp(4))*len(u.rows)
				max := gtx.Dp(unit.Dp(150))
				if height > max {
					height = max
				}
				gtx.Constraints.Max.Y = height
				gtx.Constraints.Min.Y = height
				return u.list.Layout(gtx, len(u.rows), func(gtx layout.Context, i int) layout.Dimensions {
					row := &u.rows[i]
					return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						gtx.Constraints.Max.X = gtx.Dp(unit.Dp(280))
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								gtx.Constraints.Min.X = gtx.Dp(unit.Dp(72))
								l := material.Body1(u.th, row.prefix)
								l.Font.Typeface = "Go Mono"
								return l.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Inset{Left: unit.Dp(6), Right: unit.Dp(6)}.Layout(gtx, material.Body1(u.th, "→").Layout)
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return u.field(gtx, &row.edit, prefixInvalid(row.prefix, row.edit.Text()))
							}),
						)
					})
				})
			}),
		)
	})
}

func (u *ui) editors(gtx layout.Context) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return u.editorPane(gtx, "Input", &u.input, "Paste a running-config or command output", false)
		}),
		layout.Rigid(u.hspace(10)),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Flexed(1, material.Body1(u.th, "Obfuscated output").Layout),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return u.button(gtx, &u.copyBtn, "Copy", u.output.Len() > 0, false)
						}),
						layout.Rigid(u.hspace(8)),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return u.button(gtx, &u.saveBtn, "Save", u.output.Len() > 0 && !u.busy, false)
						}),
					)
				}),
				layout.Rigid(u.gap(4)),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return u.darkEditor(gtx, &u.output, "Obfuscated text appears here")
				}),
			)
		}),
	)
}

func (u *ui) editorPane(gtx layout.Context, title string, ed *widget.Editor, hint string, _ bool) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(material.Body1(u.th, title).Layout),
		layout.Rigid(u.gap(4)),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return u.darkEditor(gtx, ed, hint)
		}),
	)
}

func (u *ui) summarySection(gtx layout.Context) layout.Dimensions {
	return u.card(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(material.H6(u.th, "Redaction summary").Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				l := material.Body2(u.th, u.summary)
				l.Color = rgb(0x1c2430)
				return l.Layout(gtx)
			}),
		)
	})
}

func (u *ui) statusLine(gtx layout.Context) layout.Dimensions {
	col := rgb(0x526072)
	switch u.statusKind {
	case "ok":
		col = rgb(0x0f766e)
	case "warn":
		col = rgb(0x92400e)
	case "error":
		col = rgb(0x9f1239)
	}
	l := material.Body2(u.th, u.status)
	l.Color = col
	return l.Layout(gtx)
}

func (u *ui) card(gtx layout.Context, inner layout.Widget) layout.Dimensions {
	return widget.Border{
		Color:        rgb(0xd5deea),
		CornerRadius: unit.Dp(10),
		Width:        unit.Dp(1),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		macro := op.Record(gtx.Ops)
		dims := layout.UniformInset(unit.Dp(12)).Layout(gtx, inner)
		call := macro.Stop()
		w := gtx.Constraints.Max.X
		if dims.Size.X < w {
			dims.Size.X = w
		}
		paint.FillShape(gtx.Ops, rgb(0xffffff), clip.Rect{Max: dims.Size}.Op())
		call.Add(gtx.Ops)
		return dims
	})
}

func (u *ui) button(gtx layout.Context, click *widget.Clickable, label string, enabled, primary bool) layout.Dimensions {
	if !enabled {
		gtx = gtx.Disabled()
	}
	b := material.Button(u.th, click, label)
	b.TextSize = unit.Sp(14)
	b.Inset = layout.Inset{Top: unit.Dp(8), Bottom: unit.Dp(8), Left: unit.Dp(12), Right: unit.Dp(12)}
	if !primary {
		b.Background = rgb(0xe8eef6)
		b.Color = rgb(0x1c2430)
	}
	return b.Layout(gtx)
}

func (u *ui) labeledEditor(gtx layout.Context, label string, ed *widget.Editor, width unit.Dp) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			l := material.Caption(u.th, label)
			l.Color = rgb(0x526072)
			return l.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			gtx.Constraints.Min.X = gtx.Dp(width)
			gtx.Constraints.Max.X = gtx.Dp(width)
			return u.field(gtx, ed, false)
		}),
	)
}

func (u *ui) field(gtx layout.Context, ed *widget.Editor, invalid bool) layout.Dimensions {
	border := rgb(0xc5d0de)
	fg := rgb(0x1c2430)
	if invalid {
		border = rgb(0x9f1239)
		fg = rgb(0x9f1239)
	}
	return widget.Border{Color: border, CornerRadius: unit.Dp(6), Width: unit.Dp(1)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Top: unit.Dp(6), Bottom: unit.Dp(6), Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			style := material.Editor(u.th, ed, "")
			style.Font.Typeface = "Go Mono"
			style.TextSize = unit.Sp(14)
			style.Color = fg
			return style.Layout(gtx)
		})
	})
}

func (u *ui) darkEditor(gtx layout.Context, ed *widget.Editor, hint string) layout.Dimensions {
	size := gtx.Constraints.Max
	if size.X < gtx.Constraints.Min.X {
		size.X = gtx.Constraints.Min.X
	}
	if size.Y < gtx.Constraints.Min.Y {
		size.Y = gtx.Constraints.Min.Y
	}
	defer clip.RRect{
		Rect: image.Rectangle{Max: size},
		NE:   gtx.Dp(8), NW: gtx.Dp(8), SE: gtx.Dp(8), SW: gtx.Dp(8),
	}.Push(gtx.Ops).Pop()
	paint.ColorOp{Color: rgb(0x0f172a)}.Add(gtx.Ops)
	paint.PaintOp{}.Add(gtx.Ops)
	layout.UniformInset(unit.Dp(8)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		style := material.Editor(u.th, ed, hint)
		style.Font.Typeface = "Go Mono"
		style.TextSize = unit.Sp(13)
		style.Color = rgb(0xe7eef8)
		style.HintColor = rgb(0x94a3b8)
		return style.Layout(gtx)
	})
	return layout.Dimensions{Size: size}
}

func (u *ui) hspace(dp unit.Dp) layout.Widget {
	return func(gtx layout.Context) layout.Dimensions {
		return layout.Spacer{Width: dp}.Layout(gtx)
	}
}

func (u *ui) noteInput() {
	text := u.input.Text()
	if text == u.inputSeen {
		return
	}
	u.inputSeen = text
	u.refreshPrefixes()
	u.applied = u.prefixSignature()
}

func (u *ui) notePrefixes() {
	sig := u.prefixSignature()
	if sig == u.applied {
		return
	}
	u.applied = sig
	if u.hasOutput && strings.TrimSpace(u.input.Text()) != "" {
		u.obfuscate()
	}
}

func (u *ui) refreshPrefixes() {
	found, err := u.eng.Scan(u.input.Text())
	if err != nil {
		u.setStatus("Could not read the IPv4 prefixes in this text.", "error")
		return
	}
	sig := strings.Join(found, "\n")
	if sig == u.prefixSig {
		return
	}
	prev := make(map[string]string, len(u.rows))
	for i := range u.rows {
		prev[u.rows[i].prefix] = u.rows[i].edit.Text()
	}
	u.prefixSig = sig
	rows := make([]prefixRow, len(found))
	for i, prefix := range found {
		rows[i].prefix = prefix
		rows[i].edit.SingleLine = true
		if value, ok := prev[prefix]; ok {
			rows[i].edit.SetText(value)
		} else {
			rows[i].edit.SetText(prefix)
		}
	}
	u.rows = rows
}

func (u *ui) prefixSignature() string {
	var b strings.Builder
	for i := range u.rows {
		b.WriteString(u.rows[i].prefix)
		b.WriteByte('=')
		b.WriteString(u.rows[i].edit.Text())
		b.WriteByte('\n')
	}
	return b.String()
}

func (u *ui) setAll() {
	value := strings.TrimSpace(u.prefixAll.Text())
	if !strings.Contains(value, ".") {
		u.setStatus("A prefix needs a dot, for example x.x.", "warn")
		return
	}
	if len(u.rows) == 0 {
		u.setStatus("No IPv4 prefixes to change yet.", "warn")
		return
	}
	for i := range u.rows {
		u.rows[i].edit.SetText(value)
	}
	u.applied = u.prefixSignature()
	if strings.TrimSpace(u.input.Text()) != "" {
		u.obfuscate()
	}
}

func (u *ui) obfuscate() {
	text := u.input.Text()
	if strings.TrimSpace(text) == "" {
		u.output.SetText("")
		u.hasOutput = false
		u.summary = emptySummary
		u.setStatus("Paste a configuration or choose a file.", "warn")
		return
	}
	repl := make(map[string]string, len(u.rows))
	invalid := false
	for i := range u.rows {
		repl[u.rows[i].prefix] = u.rows[i].edit.Text()
		if prefixInvalid(u.rows[i].prefix, u.rows[i].edit.Text()) {
			invalid = true
		}
	}
	result, err := u.eng.Process(text, u.platform.key(), u.placeholderValue(), repl)
	if err != nil {
		u.output.SetText("")
		u.hasOutput = false
		u.summary = emptySummary
		u.setStatus("Could not obfuscate this text.", "error")
		return
	}
	u.output.SetText(result.Output)
	u.hasOutput = true
	u.summary = summaryText(result)
	kind := "ok"
	message := statusMessage(u.platform.key(), result)
	if invalid {
		kind = "warn"
		message += " A prefix without a dot was left unchanged. Use a value like x.x."
	}
	u.setStatus(message, kind)
}

func (u *ui) placeholderValue() string {
	if u.placeholder.key() == "custom" {
		return u.custom.Text()
	}
	return u.placeholder.key()
}

func (u *ui) clear() {
	u.input.SetText("")
	u.output.SetText("")
	u.inputSeen = ""
	u.rows = nil
	u.prefixSig = ""
	u.applied = ""
	u.hasOutput = false
	u.platform.selected = 0
	u.platform.open = false
	u.summary = emptySummary
	u.setStatus("Cleared. The config is not stored.", "ok")
}

func (u *ui) chooseFile() {
	u.busy = true
	go func() {
		r, err := u.expl.ChooseFile()
		if err != nil {
			u.ioCh <- ioResult{err: err}
			u.win.Invalidate()
			return
		}
		defer r.Close()
		b, readErr := io.ReadAll(io.LimitReader(r, maxFileBytes+1))
		if readErr != nil {
			u.ioCh <- ioResult{err: errString("Could not read that file.")}
			u.win.Invalidate()
			return
		}
		if len(b) > maxFileBytes {
			u.ioCh <- ioResult{err: errString("That file is larger than 2 MB. Choose a smaller text file.")}
			u.win.Invalidate()
			return
		}
		text, prepErr := prepareText(b)
		u.ioCh <- ioResult{text: text, err: prepErr}
		u.win.Invalidate()
	}()
}

func (u *ui) saveOutput(text string) {
	u.busy = true
	go func() {
		w, err := u.expl.CreateFile("obfuscated.cfg")
		if err != nil {
			u.ioCh <- ioResult{err: err}
			u.win.Invalidate()
			return
		}
		_, werr := io.WriteString(w, text)
		cerr := w.Close()
		if werr == nil {
			werr = cerr
		}
		if werr != nil {
			u.ioCh <- ioResult{saved: true, err: errString("Could not save the file.")}
		} else {
			u.ioCh <- ioResult{saved: true}
		}
		u.win.Invalidate()
	}()
}

func (u *ui) pollIO() {
	select {
	case result := <-u.ioCh:
		u.busy = false
		if errors.Is(result.err, explorer.ErrUserDecline) {
			return
		}
		if result.err != nil {
			u.setStatus(result.err.Error(), "error")
			return
		}
		if result.saved {
			u.setStatus("Saved the obfuscated config.", "ok")
			return
		}
		u.input.SetText(result.text)
		u.inputSeen = "\x00"
		u.noteInput()
		u.obfuscate()
	default:
	}
}

func (u *ui) setStatus(message, kind string) {
	u.status = message
	u.statusKind = kind
}

func prepareText(b []byte) (string, error) {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
	b = bytes.ReplaceAll(b, []byte{0}, nil)
	text := string(b)
	if strings.TrimSpace(text) == "" {
		return "", errString("That file did not contain readable text.")
	}
	return text, nil
}

func prefixInvalid(prefix, value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && value != prefix && !strings.Contains(value, ".")
}

func statusMessage(platform string, result Result) string {
	if result.Uncertain {
		return "Detection was uncertain, so the platform is unknown. Secret patterns were still applied. Set the platform if you know it."
	}
	label := result.PlatformLabel
	if label == "" {
		label = "Unknown"
	}
	if platform == "auto" {
		return "Detected " + label + "."
	}
	return "Using " + label + "."
}

func summaryText(result Result) string {
	total := 0
	for _, n := range result.Counts {
		total += n
	}
	var b strings.Builder
	if total == 1 {
		b.WriteString("1 secret field replaced.")
	} else {
		fmt.Fprintf(&b, "%d secret fields replaced.", total)
	}
	switch result.AddressesRewritten {
	case 0:
	case 1:
		b.WriteString("\n1 IPv4 address had its first two octets rewritten.")
	default:
		fmt.Fprintf(&b, "\n%d IPv4 addresses had their first two octets rewritten.", result.AddressesRewritten)
	}
	if total == 0 {
		b.WriteString("\nNo secret fields matched. A password hidden in a description, banner, or unusual command may still be present.")
		return b.String()
	}
	for _, category := range result.Categories {
		n := result.Counts[category.ID]
		if n == 0 {
			continue
		}
		fmt.Fprintf(&b, "\n%s: %d", category.Label, n)
	}
	return b.String()
}

func rgb(v uint32) color.NRGBA {
	return color.NRGBA{R: uint8(v >> 16), G: uint8(v >> 8), B: uint8(v), A: 0xff}
}
