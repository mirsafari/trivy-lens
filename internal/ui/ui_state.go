package ui

import (
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
)

type uiState struct {
	// table is the Bubble Tea table component displaying the CVEs
	table table.Model

	// viewport displays detailed information about the selected CVE
	viewport viewport.Model

	// reportedSpinner is the spinner shown while fetching vulnerability reports
	reportedSpinner spinner.Model

	// whitelistedSpinner is the spinner shown while fetching whitelisted CVEs
	whitelistedSpinner spinner.Model

	// terminalWidth is the current width of the terminal window
	terminalWidth int

	// terminalHeight is the current height of the terminal window
	terminalHeight int

	// severityFilterIndex is the current index into severityList for filtering CVEs by severity
	severityFilterIndex int

	// cveSearchInput contains the string typed into the search box that will be used for filtering
	cveSearchInput textinput.Model

	// isSearching indicates if the CVE search is in focus and user is typing inside of it
	isSearching bool

	// help contains the information for footer text with key bindings and context info
	help help.Model
}
