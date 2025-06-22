package kube

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	VulnerabilityReportGVR = schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}
)

// FetchVulnerabilityReports retrieves all Trivy VulnerabilityReports from all namespaces
// and converts them into typed v1alpha1.VulnerabilityReport objects.
func FetchVulnerabilityReports(client dynamic.Interface) ([]v1alpha1.VulnerabilityReport, error) {
	unstructuredReports, err := fetchVulnReportsRaw(client)
	if err != nil {
		return nil, fmt.Errorf("Error fetching VulnerabilityReports: %w", err)
	}

	parsedReports, err := parseVulnReports(unstructuredReports)
	if err != nil {
		return nil, fmt.Errorf("Error structuring VulnerabilityReports: %w", err)
	}

	return parsedReports, nil
}

func fetchVulnReportsRaw(client dynamic.Interface) (unstructured.UnstructuredList, error) {

	vulnReports, err := client.Resource(VulnerabilityReportGVR).Namespace("").List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		return unstructured.UnstructuredList{}, err
	}

	return *vulnReports, nil
}

// parseVulnReports converts a list of unstructured Kubernetes objects into strongly-typed Trivy VulnerabilityReports.
//
// Any report that fails to deserialize is skipped with a warning, and valid reports are returned.

func parseVulnReports(reports unstructured.UnstructuredList) ([]v1alpha1.VulnerabilityReport, error) {

	var parsedReports []v1alpha1.VulnerabilityReport

	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return parsedReports, fmt.Errorf("Error registering scheme: %v", err)
	}

	// Deserialize each item into VulnerabilityReport
	for _, item := range reports.Items {
		vulnReport := &v1alpha1.VulnerabilityReport{}
		err := scheme.Convert(&item, vulnReport, nil)

		if err != nil {
			slog.Warn("Could not deserialize vulnerability report", "name", item.GetName(), "err", err)
			continue
		}

		parsedReports = append(parsedReports, *vulnReport)
	}
	return parsedReports, nil
}
