package ui

import (
	"fmt"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mirsafari/trivy-lens/internal/config"
	"github.com/mirsafari/trivy-lens/internal/kube"
	"github.com/mirsafari/trivy-lens/internal/trivy"
	"k8s.io/client-go/dynamic"
)

type dataModel struct {
	// reportedCVEs contains the fetched CVE vulnerability reports, keyed by CVE ID
	reportedCVEs trivy.ReportedCVEs

	// whitelistedCVEs contains CVEs that are whitelisted, keyed by CVE ID, with expiry info
	whitelistedCVEs trivy.WhitelistedCVEs

	// loadingReported tracks whether vulnerability reports are still loading
	loadingReported bool

	// loadingWhitelisted tracks whether the whitelist data is still loading
	loadingWhitelisted bool

	// ready indicates whether CVE data has been loaded and views are initialized
	ready bool

	// err stores any fatal error that should be displayed before quitting
	err error
}

type appContext struct {
	// k8sClient is the dynamic Kubernetes client used for fetching CVE data.
	k8sClient dynamic.Interface

	// appConfig holds user configuration and application settings.
	appConfig config.Config
}

var severityList = []string{
	"ALL",
	string(v1alpha1.SeverityCritical),
	string(v1alpha1.SeverityHigh),
	string(v1alpha1.SeverityMedium),
	string(v1alpha1.SeverityLow),
}

type CVEsFetchedMsg struct {
	Data trivy.ReportedCVEs
}

type IgnoreListParsedMsg struct {
	Data trivy.WhitelistedCVEs
}

func fetchReportedCVEs(client dynamic.Interface) tea.Cmd {
	return func() tea.Msg {
		vulnReportedList, err := kube.FetchVulnerabilityReports(client)
		if err != nil {
			return fmt.Errorf("could not fetch vulnerability reports %w", err)
		}

		parsedVulns := trivy.BuildCVEMap(vulnReportedList)

		return CVEsFetchedMsg{Data: parsedVulns}
	}
}

func fetchWhitelistedCVEs(client dynamic.Interface, cfg config.Config) tea.Cmd {
	return func() tea.Msg {
		vulnIgnored, err := kube.FetchTrivyIgnoreFile(client, cfg.TrivyNamespace, cfg.TrivyConfigMapName)
		if err != nil {
			return fmt.Errorf("could not fetch Trivy ignore file %w", err)
		}

		parsedIgnoreList, err := trivy.ParseIgnoreFile(vulnIgnored)
		if err != nil {
			return fmt.Errorf("failed parsing ignoreList: %w", err)
		}

		return IgnoreListParsedMsg{Data: parsedIgnoreList}
	}
}
