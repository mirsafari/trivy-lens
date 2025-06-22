package trivy

import (
	"strings"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

// BuildCVEMap takes a slice of VulnerabilityReports and consolidates
// the CVEs into a map keyed by CVE ID, aggregating severity, score,
// and affected images.
//
// Reports without a score are ignored.
func BuildCVEMap(reports []v1alpha1.VulnerabilityReport) ReportedCVEs {

	vulns := make(ReportedCVEs)

	for _, r := range reports {
		for _, v := range r.Report.Vulnerabilities {

			if v.Score == nil {
				continue
			}

			imgReport := Image{
				Repository: r.Report.Artifact.Repository,
				Tag:        r.Report.Artifact.Tag,
				Namespace:  r.Namespace,
				Object:     r.Name,
			}

			if entry, exists := vulns[v.VulnerabilityID]; exists {
				entry.Images = append(entry.Images, imgReport)
				vulns[v.VulnerabilityID] = entry
			} else {
				vulns[v.VulnerabilityID] = CVEReport{
					Score:    *v.Score,
					Severity: string(v.Severity),
					Images:   []Image{imgReport},
					Title:    v.Title,
				}
			}
		}
	}
	return vulns
}

// ParseIgnoreFile parses a Trivy-formatted ignore file string, returning a map of CVE IDs
// to their expiration dates. Lines in the ignore file are expected to have the
// format "<CVE_ID> exp:<YYYY-MM-DD>".
//
// Invalid date formats are skipped with a warning printed to stdout.
func ParseIgnoreFile(raw string) (WhitelistedCVEs, error) {

	whitelistedCVEs := make(WhitelistedCVEs)
	const layout = "2006-01-02"

	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.HasPrefix(fields[1], "exp:") {
			cveID := fields[0]

			exp := strings.TrimPrefix(fields[1], "exp:")
			expDate, err := time.Parse(layout, exp)
			if err != nil {
				continue
			}
			whitelistedCVEs[cveID] = expDate
		}
	}

	return whitelistedCVEs, nil
}
