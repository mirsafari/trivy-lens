package kube

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	ConfigMapGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "configmaps",
	}
	TrivyConfigIgnoreFileKey string = "trivy.ignoreFile"
)

// FetchTrivyIgnoreFile retrieves the contents of the "trivy.ignoreFile" key from a ConfigMap.
//
// It looks up the specified ConfigMap in the given namespace using the dynamic Kubernetes client,
// and extracts the value stored under the "data.trivy.ignoreFile" field.
//
// Parameters:
//   - client: a Kubernetes dynamic client.
//   - ns: the namespace where the ConfigMap resides.
//   - cfgMapName: the name of the ConfigMap to retrieve.
//
// Returns:
//   - string: the raw ignore file content as a single string.
//   - error: if the ConfigMap could not be retrieved, parsed, or the key was missing.
//
// Example:
//
//	ignoreFileRaw, err := kube.FetchTrivyIgnoreFile(client, "trivy-operator", "trivy-operator-config")
//	if err != nil {
//	    log.Fatalf("failed to get ignore file: %v", err)
//	}
func FetchTrivyIgnoreFile(client dynamic.Interface, ns, cfgMapName string) (string, error) {
	cm, err := client.
		Resource(ConfigMapGVR).
		Namespace(ns).
		Get(context.TODO(), cfgMapName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("Failed to get ConfigMap: %w", err)
	}

	data, found, err := unstructured.NestedStringMap(cm.Object, "data")
	if err != nil || !found {
		return "", fmt.Errorf("Failed to extract ConfigMap data: %w", err)
	}

	ignoreFileRaw, ok := data[TrivyConfigIgnoreFileKey]
	if !ok {
		return "", fmt.Errorf("Missing 'trivy.ignoreFile' key in ConfigMap %s", cfgMapName)
	}

	return ignoreFileRaw, nil
}
