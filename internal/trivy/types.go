package trivy

import "time"

// ReportedCVEs maps CVE IDs to their detailed vulnerability reports.
type ReportedCVEs map[string]CVEReport

// CVEReport represents detailed information about a specific CVE,
// including its severity score and the list of images affected by it.
type CVEReport struct {
	// CVSS score of the vulnerability
	Score float64
	// Severity level of the CVE (e.g., "CRITICAL", "HIGH")
	Severity string
	// List of container images affected by this CVE
	Images []Image
	// Vulnerability title containing basic description about vulnerability
	Title string
}

// Image represents a container image affected by a CVE, identified by
// its Kubernetes namespace, object name, repository, and tag.
type Image struct {
	// Kubernetes namespace of the affected resource
	Namespace string
	// Name of the Kubernetes object (e.g., ReplicaSet, StatefulSet)
	Object string
	// Container image repository (e.g., nginx)
	Repository string
	// Image tag/version (e.g., latest, v1.2.3)
	Tag string
}

// WhitelistedCVEs maps CVE IDs to their expiration dates, representing
// CVEs that are temporarily ignored or allowed until the specified time.
type WhitelistedCVEs map[string]time.Time
