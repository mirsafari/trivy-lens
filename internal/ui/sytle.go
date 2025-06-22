package ui

import (
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
)

const banner string = `
 _____     _               _                   
|_   _| __(_)_   ___   _  | |    ___ _ __  ___ 
  | || '__| \ \ / / | | | | |   / _ \ '_ \/ __|
  | || |  | |\ V /| |_| | | |__|  __/ | | \__ \
  |_||_|  |_| \_/  \__, | |_____\___|_| |_|___/
                   |___/
`

// Color codes 256 ANSI
const bayLeaf string = "108"
const darkGrayishRed string = "138"
const grayishBlue string = "146"

const chineseGreen string = "185"

const pearlAqua string = "115"
const blackOlive string = "237"

const mediumTurquoise string = "80"
const vampireBlack string = "232"

var (
	// Color variants
	successColor = lipgloss.Color(bayLeaf)
	warningColor = lipgloss.Color(darkGrayishRed)
	infoColor    = lipgloss.Color(grayishBlue)

	primaryColorFG   = lipgloss.Color(chineseGreen)
	secondaryColorFG = lipgloss.Color(pearlAqua)
	secondaryColorBG = lipgloss.Color(blackOlive)
	accentColorFG    = lipgloss.Color(mediumTurquoise)
	accentColorBG    = lipgloss.Color(vampireBlack)

	primaryStyle   = lipgloss.NewStyle().Foreground(primaryColorFG)
	secondaryStyle = lipgloss.NewStyle().Foreground(secondaryColorFG).Background(secondaryColorBG)
	accentStyle    = lipgloss.NewStyle().Foreground(accentColorFG).Background(accentColorBG)

	whitelistedStyleFG = lipgloss.NewStyle().Foreground(successColor)
	expiredStyleFG     = lipgloss.NewStyle().Foreground(warningColor)
	activeStyleFG      = lipgloss.NewStyle().Foreground(infoColor)

	// Generic
	borderNormalPrimary = lipgloss.NewStyle().
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(primaryColorFG)

	borderBanner = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(accentColorFG).
			Bold(true)

	// Details view
	detailTitleStyle = secondaryStyle.
				Bold(true).
				Padding(0, 1)
	detailHeaderStyle = lipgloss.NewStyle().Bold(true).Underline(true)
	namespaceLabel    = lipgloss.NewStyle().Foreground(secondaryColorFG).Render("Namespace")
	objectLabel       = lipgloss.NewStyle().Foreground(secondaryColorFG).Render("Object")

	// Table style
	tableStyle         = table.DefaultStyles().Header.BorderStyle(lipgloss.NormalBorder()).BorderForeground(primaryColorFG).BorderBottom(true).Bold(false)
	tableStyleSelected = table.DefaultStyles().Selected.Foreground(secondaryColorFG).Background(secondaryColorBG).Bold(false)
)
