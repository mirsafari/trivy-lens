package kube

import (
	"fmt"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// NewDynamicClient creates a new Kubernetes dynamic client using the provided kubeconfig path.
//
// It builds a REST configuration from the kubeconfig file and then uses it to initialize
// a dynamic client, which can be used to interact with arbitrary Kubernetes resources.
//
// Parameters:
//   - kubeconfig: the path to a kubeconfig file (e.g., "~/.kube/config").
//
// Returns:
//   - dynamic.Interface: a Kubernetes dynamic client for interacting with resources.
//   - error: if the kubeconfig could not be loaded or the client could not be created.
//
// Example:
//
//	client, err := kube.NewDynamicClient("/home/user/.kube/config")
//	if err != nil {
//	    log.Fatalf("Failed to create client: %v", err)
//	}
func NewDynamicClient(kubeconfig string) (dynamic.Interface, error) {
	restConfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Error building kubeconfig: %w", err)
	}

	return dynamic.NewForConfig(restConfig)
}

func GetKubecontextName(kubeconfigPath string) string {
	loadingRules := &clientcmd.ClientConfigLoadingRules{
		ExplicitPath: kubeconfigPath,
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, nil)

	rawConfig, err := clientConfig.RawConfig()
	if err != nil {
		return "N/A"
	}
	return rawConfig.CurrentContext
}
