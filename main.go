package main

import (
	"fmt"
	"os"

	"gioui.org/app"
	"gioui.org/unit"
)

func main() {
	eng, err := newEngine()
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not start")
		os.Exit(1)
	}
	ui := newUI(eng)
	go func() {
		w := new(app.Window)
		w.Option(
			app.Title("Config Obfuscator"),
			app.Size(unit.Dp(1100), unit.Dp(780)),
			app.MinSize(unit.Dp(860), unit.Dp(640)),
		)
		if err := ui.run(w); err != nil {
			fmt.Fprintln(os.Stderr, "window closed:", err)
		}
		os.Exit(0)
	}()
	app.Main()
}
