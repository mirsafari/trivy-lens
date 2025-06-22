package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/tree"
)

const (
	viewportPadding = 2
	terminalPadding = 20
)

func (m *model) setupViews() {
	m.buildTable()

	// Calculate width for table and viewport
	tableWidth := m.ui.terminalWidth / 2
	viewportWidth := m.ui.terminalWidth - tableWidth - viewportPadding

	m.ui.table.SetWidth(tableWidth)
	m.ui.table.SetHeight(m.ui.terminalHeight - terminalPadding)

	m.ui.viewport = viewport.New(viewportWidth, m.ui.terminalHeight-terminalPadding+viewportPadding)
	m.ui.viewport.Style = borderNormalPrimary
	m.ui.viewport.SetContent(m.buildDetailViewContent())

	m.data.ready = true
}

// loadingView renders the UI while data is being fetched.
func (m *model) loadingView() string {
	var reportedStatus, whitelistedStatus string

	if m.data.loadingReported {
		reportedStatus = fmt.Sprintf("%s Fetching vulnerability reports...", m.ui.reportedSpinner.View())
	} else {
		reportedStatus = primaryStyle.Render("✓") + " Vulnerability reports fetched."
	}

	if m.data.loadingWhitelisted {
		whitelistedStatus = fmt.Sprintf("%s Fetching whitelisted CVEs...", m.ui.whitelistedSpinner.View())
	} else {
		whitelistedStatus = primaryStyle.Render("✓") + " Whitelisted CVEs fetched."
	}

	padding := (m.ui.terminalWidth / 2) - 20
	paddingStyle := lipgloss.NewStyle().Width(padding).Render("")

	reportedCenter := lipgloss.JoinHorizontal(lipgloss.Center, paddingStyle, reportedStatus, paddingStyle)
	whitelistedCenter := lipgloss.JoinHorizontal(lipgloss.Center, paddingStyle, whitelistedStatus, paddingStyle)

	status := lipgloss.JoinVertical(0, reportedCenter, whitelistedCenter)

	return status
}

func (m *model) buildDetailViewContent() string {
	// Ensure there's a selected row before accessing it.
	if len(m.ui.table.SelectedRow()) == 0 {
		return "No selection."
	}
	selectedCVEID := m.ui.table.SelectedRow()[0]
	report := m.data.reportedCVEs[selectedCVEID]

	var content strings.Builder

	// Title
	content.WriteString(detailTitleStyle.Render(selectedCVEID) + "\n\n")

	// Details Section
	content.WriteString(detailHeaderStyle.Render("Details") + "\n")
	content.WriteString(fmt.Sprintf("Severity: %s\n", report.Severity))
	content.WriteString(fmt.Sprintf("CVSS Score: %.1f\n", report.Score))
	content.WriteString(fmt.Sprintf("Info: %s\n\n", report.Title)) // TODO: Split to multiple lines if too long

	// Affected Images Section
	content.WriteString(detailHeaderStyle.Render("Affected Images") + "\n")
	if len(report.Images) == 0 {
		content.WriteString("No container images reported for this CVE.\n")
	} else {

		imageGroup := make(map[string][]string)
		for _, img := range report.Images {
			key := fmt.Sprintf("%s:%s", img.Repository, img.Tag)

			imageGroup[key] = append(imageGroup[key], fmt.Sprintf("%s: %s; %s: %s", namespaceLabel, img.Namespace, objectLabel, img.Object))
		}

		t := tree.New()
		for k, v := range imageGroup {
			subTree := tree.New().Root(k)

			for _, obj := range v {
				subTree.Child(obj)
			}
			t.Child(subTree)
		}
		content.WriteString(t.String())

	}

	return content.String()
}

func (m *model) buildHeader() string {

	sourceInformation := fmt.Sprintf("Vulnerabilities fetched from kubectl context: %s\n", accentStyle.Render(m.ctx.appConfig.KubecontextName))
	severityFilter := fmt.Sprintf("Severity filter: %s\n", accentStyle.Render(severityList[m.ui.severityFilterIndex]))

	searchView := fmt.Sprintf("CVE Search: %s\n", m.ui.cveSearchInput.View())
	if m.ui.isSearching {
		searchView = primaryStyle.Render(searchView)
	}

	actionsDisplay := lipgloss.JoinVertical(0, sourceInformation, severityFilter, searchView)
	actionsDisplay = lipgloss.NewStyle().PaddingLeft(3).PaddingTop(1).Render(actionsDisplay)

	rightBox := borderBanner.Render(primaryStyle.Render(banner))

	availableSpace := m.ui.terminalWidth - lipgloss.Width(actionsDisplay) - lipgloss.Width(rightBox)
	emptySpace := lipgloss.NewStyle().Width(availableSpace).Render("")

	return lipgloss.JoinHorizontal(lipgloss.Left, actionsDisplay, emptySpace, rightBox)
}

func (m *model) buildFooter() string {

	totalRows := len(m.ui.table.Rows())
	cursor := m.ui.table.Cursor()
	if totalRows == 0 {
		cursor = -1 // Display 0 when the table is empty
	}
	positionInfo := fmt.Sprintf("%d/%d", cursor+1, totalRows)

	footer := fmt.Sprintf(
		"%s\n\n%s\n",
		accentStyle.Render(positionInfo),
		m.ui.help.View(defaultKeyMap),
	)

	footer = lipgloss.NewStyle().
		Align(lipgloss.Center).
		Padding(1).
		Render(footer)

	padding := (m.ui.terminalWidth - lipgloss.Width(footer)) / 2
	paddingStyle := lipgloss.NewStyle().Width(padding).Render("")
	finalOutput := lipgloss.JoinHorizontal(lipgloss.Center, paddingStyle, footer, paddingStyle)

	return finalOutput
}
