package main

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

// The legacy Fyne frontend uses the same logo as the Avalonia application.
//
//go:embed TKNetUI/Assets/sonar-uygulama.png
var sonarLogo []byte

var resourceSonarIcon = &fyne.StaticResource{
	StaticName:    "sonar-uygulama.png",
	StaticContent: sonarLogo,
}
