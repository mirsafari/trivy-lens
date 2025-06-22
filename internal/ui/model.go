package ui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/mirsafari/trivy-lens/internal/config"
	"k8s.io/client-go/dynamic"

	tea "github.com/charmbracelet/bubbletea"
)

// model holds the UI state and data for the application.
// It implements the Bubble Tea model interface with Init, Update, and View methods.
type model struct {
	data dataModel
	ui   uiState
	ctx  appContext
}

// NewModel creates a new UI model with Kubernetes client and config.
func NewModel(client dynamic.Interface, cfg config.Config) model {
	rs := spinner.New()
	rs.Spinner = spinner.Points
	rs.Style = accentStyle

	ws := spinner.New()
	ws.Spinner = spinner.Points
	ws.Style = accentStyle

	severityFilterIndex := 0
	for i, severity := range severityList {
		if severity == string(cfg.CVESeverity) {
			severityFilterIndex = i
		}
	}

	cveInput := textinput.New()
	cveInput.Placeholder = "CVE-2024-..."
	cveInput.CharLimit = 30
	cveInput.Width = 30

	help := help.New()
	help.ShowAll = true
	help.FullSeparator = " | "
	help.Styles.FullKey = primaryStyle

	return model{
		ctx: appContext{
			k8sClient: client,
			appConfig: cfg,
		},
		ui: uiState{
			reportedSpinner:     rs,
			whitelistedSpinner:  ws,
			severityFilterIndex: severityFilterIndex,
			cveSearchInput:      cveInput,
			help:                help,
		},
		data: dataModel{
			loadingReported:    true,
			loadingWhitelisted: true,
		},
	}

}

// Init is called once when the application starts.
func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.ui.reportedSpinner.Tick,
		m.ui.whitelistedSpinner.Tick,
		fetchReportedCVEs(m.ctx.k8sClient),
		fetchWhitelistedCVEs(m.ctx.k8sClient, m.ctx.appConfig),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.ui.isSearching {
			switch {
			case key.Matches(msg, defaultKeyMap.ExitSearch):
				m.ui.isSearching = false
				m.ui.cveSearchInput.Blur()
				return m, nil

			default:
				var inputCmd tea.Cmd
				m.ui.cveSearchInput, inputCmd = m.ui.cveSearchInput.Update(msg)
				m.buildTable()
				m.ui.table.SetCursor(0)
				m.ui.viewport.SetContent(m.buildDetailViewContent())
				return m, inputCmd
			}
		}

		switch {
		case key.Matches(msg, defaultKeyMap.Quit):
			return m, tea.Quit

		case key.Matches(msg, defaultKeyMap.Search):
			m.ui.isSearching = true
			m.ui.cveSearchInput.Focus()
			return m, textinput.Blink

		case key.Matches(msg, defaultKeyMap.Filter):
			if m.data.ready {
				m.ui.severityFilterIndex = (m.ui.severityFilterIndex + 1) % len(severityList)
				m.buildTable()
				m.ui.table.SetCursor(0)
				m.ui.viewport.SetContent(m.buildDetailViewContent())
			}
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.ui.terminalWidth = msg.Width
		m.ui.terminalHeight = msg.Height
		if m.data.ready {
			m.setupViews()
		}

	case CVEsFetchedMsg:
		m.data.reportedCVEs = msg.Data
		m.data.loadingReported = false
		if !m.data.loadingWhitelisted {
			m.setupViews()
		}

		return m, nil

	case IgnoreListParsedMsg:
		m.data.whitelistedCVEs = msg.Data
		m.data.loadingWhitelisted = false
		if !m.data.loadingReported {
			m.setupViews()
		}

		return m, nil

	case error:
		m.data.err = msg
		fmt.Println(msg)
		time.Sleep(3 * time.Second) // Add sleep before quit as app is in viewport and otherwise error will not be shown
		return m, tea.Quit
	}

	// Process updates for active components.
	if !m.data.ready {
		// Update spinners while loading
		if m.data.loadingReported {
			m.ui.reportedSpinner, cmd = m.ui.reportedSpinner.Update(msg)
			cmds = append(cmds, cmd)
		}
		if m.data.loadingWhitelisted {
			m.ui.whitelistedSpinner, cmd = m.ui.whitelistedSpinner.Update(msg)
			cmds = append(cmds, cmd)
		}
	} else {
		// Synchronize views on navigation
		var oldCursor = m.ui.table.Cursor()
		m.ui.table, cmd = m.ui.table.Update(msg)
		cmds = append(cmds, cmd)

		if m.ui.table.Cursor() != oldCursor {
			m.ui.viewport.SetContent(m.buildDetailViewContent())
		}
	}
	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	if m.data.err != nil {
		return fmt.Sprintf("Fatal error: %v\n", m.data.err)
	}

	if !m.data.ready {
		return m.loadingView()
	}

	tableView := borderNormalPrimary.Render(m.ui.table.View())

	detailView := m.ui.viewport.View()
	mainView := lipgloss.JoinHorizontal(lipgloss.Top, tableView, detailView)

	header := m.buildHeader()
	footer := m.buildFooter()

	return "\n" + header + "\n" + mainView + footer
}
