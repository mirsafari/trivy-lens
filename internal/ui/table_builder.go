package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/mirsafari/trivy-lens/internal/trivy"
)

func (m *model) buildTable() {
	columns := []table.Column{
		{Title: "CVE-ID", Width: 20},
		{Title: "Severity", Width: 10},
		{Title: "Score", Width: 5},
		{Title: "Status", Width: 50},
	}

	rows := m.buildRows()

	// If table is already rendered, just update the data and return early
	if m.data.ready {
		m.ui.table.SetRows(rows)
		return
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(40),
	)

	s := table.DefaultStyles()
	s.Header = tableStyle
	s.Selected = tableStyleSelected

	t.SetStyles(s)
	m.ui.table = t
}

func (m *model) buildRows() []table.Row {
	now := time.Now()
	filtered := m.filterCVEs()
	var rows []table.Row

	for id, report := range filtered {
		row, prepend := m.buildTableRow(id, report, now)
		if prepend {
			rows = append([]table.Row{row}, rows...)
		} else {
			rows = append(rows, row)
		}
	}

	if len(rows) == 0 {
		rows = append(rows, table.Row{
			"N/A", "N/A", "N/A",
			fmt.Sprintf("No vulnerabilities of severity %s found", severityList[m.ui.severityFilterIndex]),
		})
	}

	return rows
}

func (m *model) filterCVEs() map[string]trivy.CVEReport {
	filtered := make(map[string]trivy.CVEReport)
	selectedSeverity := severityList[m.ui.severityFilterIndex]
	cveSearchFilter := strings.ToLower(m.ui.cveSearchInput.Value())

	for id, report := range m.data.reportedCVEs {
		if selectedSeverity != "ALL" && report.Severity != selectedSeverity {
			continue
		}

		if cveSearchFilter != "" && !strings.Contains(strings.ToLower(id), cveSearchFilter) {
			continue
		}

		filtered[id] = report
	}
	return filtered
}

func (m *model) buildTableRow(id string, report trivy.CVEReport, now time.Time) (table.Row, bool) {
	prepend := false

	// Put criticals on top
	severity, _ := v1alpha1.StringToSeverity(report.Severity)
	if severity == v1alpha1.SeverityCritical {
		prepend = true
	}

	if expiry, ok := m.data.whitelistedCVEs[id]; ok {
		prepend = true
		if expiry.Before(now) {
			daysAgo := int(now.Sub(expiry).Hours() / 24)
			return formatRow(id, report, fmt.Sprintf("Whitelist expired %d days ago", daysAgo), expiredStyleFG), prepend

		}
		return formatRow(id, report, fmt.Sprintf("Whitelisted until %s", expiry.Format("2006-01-02")), whitelistedStyleFG), prepend
	}

	return formatRow(id, report, "Requires Assessment", activeStyleFG), prepend
}

func formatRow(id string, report trivy.CVEReport, text string, color lipgloss.Style) table.Row {
	return table.Row{
		id,
		report.Severity,
		fmt.Sprintf("%.1f", report.Score),
		color.Render(text),
	}
}
