package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/mirsafari/trivy-lens/internal/kube"
)

// Config holds all environment-based configuration options for the vulnerability validation script.
// These variables control the behavior of Trivy report fetching and filtering logic.
type Config struct {
	// KubeconfigPath is the path to the kubeconfig file used to connect to the cluster.
	KubeconfigPath string
	// TrivyNamespace is the namespace where Trivy Operator is deployed.
	TrivyNamespace string
	// TrivyConfigMapName is the name of the ConfigMap containing the Trivy ignore list.
	TrivyConfigMapName string
	// CVEMinimalScore defines the minimum CVSS score threshold for reported vulnerabilities to be considered.
	CVEMinimalScore float64
	// CVESeverity defines the severity level to include in the report.
	CVESeverity v1alpha1.Severity
	// KubecontextName stores information about the kubectl context  name defined in local kubeconfig used to fetch the data
	KubecontextName string
}

// New returns a Config struct initialized from environment variables.
// If a variable is missing or invalid, a default value will be used and a warning will be logged.
func New() Config {
	envPrefix := "TRIVY_LENS_"
	kubeconfigPath := getEnvString(fmt.Sprintf("%sKUBECONFIG_PATH", envPrefix), fmt.Sprintf("%s/.kube/config", os.Getenv("HOME")))
	return Config{
		KubeconfigPath:     kubeconfigPath,
		TrivyNamespace:     getEnvString(fmt.Sprintf("%sTRIVY_NAMESPACE", envPrefix), "trivy-system"),
		TrivyConfigMapName: getEnvString(fmt.Sprintf("%sTRIVY_CONFIGMAPNAME", envPrefix), "trivy-operator-trivy-config"),
		CVEMinimalScore:    getEnvFloat(fmt.Sprintf("%sCVE_MINIMAL_SCORE", envPrefix), 0.0),
		CVESeverity:        getEnvSeverity(fmt.Sprintf("%sCVE_SEVERITY", envPrefix), v1alpha1.SeverityCritical),
		KubecontextName:    kube.GetKubecontextName(kubeconfigPath),
	}
}

func getEnvString(envName, defaultValue string) string {
	value, exists := os.LookupEnv(envName)

	if exists {
		return value
	}

	return defaultValue
}

func getEnvFloat(envName string, defaultValue float64) float64 {
	value, exists := os.LookupEnv(envName)

	if exists {
		val, err := strconv.ParseFloat(value, 64)
		if err == nil {
			return val
		}
		slog.Warn("Invalid float value in env var, using default", "env", envName, "default", defaultValue)
	}

	return defaultValue
}
func getEnvSeverity(envName string, defaultValue v1alpha1.Severity) v1alpha1.Severity {
	value, exists := os.LookupEnv(envName)

	if exists {
		val, err := v1alpha1.StringToSeverity(value)
		if err == nil {
			return val
		}
		slog.Warn("Invalid severity value in env var, using default", "env", envName, "default", defaultValue)
	}

	return defaultValue
}
