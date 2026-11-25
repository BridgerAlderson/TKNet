//go:build ignore

// This file contains the legacy Fyne UI that was replaced by the C# Avalonia frontend (TKNetUI).
// It is excluded from normal builds. The active entry point is engine_main.go (headless mode).

package main

import (
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/theme"

	"tknet/ui"
)

func main() {
	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme())
	a.SetIcon(resourceSonarIcon)

	mainWindow := ui.NewMainWindow(a)
	mainWindow.ShowAndRun()
}
