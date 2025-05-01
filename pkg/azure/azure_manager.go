package azure

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"keyper/pkg/common"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
)

// formatTime formats a time.Time pointer to a string
func formatTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// AzureKeyVault implements the common.SecretManager interface for Azure Key Vault
type AzureKeyVault struct {
	client   *azsecrets.Client
	ctx      context.Context
	vaultURL string
}

// getDefaultVaultURL gets the vault URL from environment variable
func getDefaultVaultURL() (string, error) {
	vaultURL := os.Getenv("AZURE_KEYVAULT_URL")
	if vaultURL == "" {
		return "", fmt.Errorf("AZURE_KEYVAULT_URL environment variable not set")
	}
	return vaultURL, nil
}

// extractSecretName extracts secret name from ID URL
func extractSecretName(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// extractVersionFromID extracts version from ID URL
func extractVersionFromID(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	return ""
}

// NewAzureKeyVault creates a new Azure Key Vault instance
func NewAzureKeyVault() common.SecretManager {
	ctx := context.Background()

	// Get vault URL from environment
	vaultURL, err := getDefaultVaultURL()
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
		vaultURL = "https://example.vault.azure.net"
	}

	// Create credential
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		fmt.Printf("Failed to create Azure credential: %v\n", err)
		return nil
	}

	// Create client
	client, err := azsecrets.NewClient(vaultURL, credential, nil)
	if err != nil {
		fmt.Printf("Failed to create Azure Key Vault client: %v\n", err)
		return nil
	}

	return &AzureKeyVault{
		client:   client,
		ctx:      ctx,
		vaultURL: vaultURL,
	}
}

// List returns all secrets in the given namespace/path
func (a *AzureKeyVault) List(namespace string) ([]common.Secret, error) {
	var secrets []common.Secret

	// In Azure, we ignore namespace as Key Vault URL already specifies the vault
	// Create a pager for listing secrets
	pager := a.client.NewListSecretsPager(nil)

	for pager.More() {
		page, err := pager.NextPage(a.ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list Azure Key Vault secrets: %w", err)
		}

		for _, secretItem := range page.Value {
			if secretItem.ID == nil {
				continue
			}

			// Extract secret name from ID
			name := extractSecretName(string(*secretItem.ID))

			// Get versions for this secret
			versions, latestVersion, err := a.getSecretVersions(name)
			if err != nil {
				// Log the error but continue with other secrets
				fmt.Printf("Warning: could not fetch versions for secret %s: %v\n", name, err)
			}

			// Extract tags/labels
			labels := make(map[string]string)
			if secretItem.Tags != nil {
				for k, v := range secretItem.Tags {
					if v != nil {
						labels[k] = *v
					}
				}
			}

			// Format creation and update times
			created := ""
			updated := ""
			if secretItem.Attributes != nil {
				if secretItem.Attributes.Created != nil {
					created = formatTime(secretItem.Attributes.Created)
				}
				if secretItem.Attributes.Updated != nil {
					updated = formatTime(secretItem.Attributes.Updated)
				}
			}

			secrets = append(secrets, common.Secret{
				Name:          name,
				Namespace:     "", // Azure doesn't use namespaces in the same way
				Provider:      "azure",
				Versions:      versions,
				LatestVersion: latestVersion,
				Labels:        labels,
				Created:       created,
				Updated:       updated,
			})
		}
	}

	return secrets, nil
}

// Get retrieves a specific secret value by name and version
func (a *AzureKeyVault) Get(namespace string, name string, version string) (*common.SecretValue, error) {
	// Determine version to get; empty string for latest
	versionToGet := ""
	if version != "" {
		versionToGet = version
	}
	result, err := a.client.GetSecret(a.ctx, name, versionToGet, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure secret: %w", err)
	}

	if result.ID == nil || result.Value == nil {
		return nil, fmt.Errorf("secret not found or has no value")
	}

	// Extract secret value
	value := *result.Value

	// Extract tags/labels
	labels := make(map[string]string)
	if result.Tags != nil {
		for k, v := range result.Tags {
			if v != nil {
				labels[k] = *v
			}
		}
	}

	// Format creation time
	created := ""
	if result.Attributes != nil && result.Attributes.Created != nil {
		created = formatTime(result.Attributes.Created)
	}

	return &common.SecretValue{
		Name:      name,
		Namespace: "", // Azure doesn't use namespaces in the same way
		Provider:  "azure",
		Value:     value,
		Version:   version,
		Labels:    labels,
		Created:   created,
	}, nil
}

// Create creates a new secret
func (a *AzureKeyVault) Create(namespace string, name string, value string, labels map[string]string) error {
	// Convert labels to tags
	tags := make(map[string]*string)
	for k, v := range labels {
		tags[k] = &v
	}

	// Create secret
	params := azsecrets.SetSecretParameters{
		Value: &value,
		Tags:  tags,
	}

	_, err := a.client.SetSecret(a.ctx, name, params, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure secret: %w", err)
	}

	return nil
}

// Update updates an existing secret
func (a *AzureKeyVault) Update(namespace string, name string, value string, labels map[string]string) error {
	// Convert labels to tags
	tags := make(map[string]*string)
	for k, v := range labels {
		tags[k] = &v
	}

	// Update secret (same as create in Azure Key Vault)
	params := azsecrets.SetSecretParameters{
		Value: &value,
		Tags:  tags,
	}

	_, err := a.client.SetSecret(a.ctx, name, params, nil)
	if err != nil {
		return fmt.Errorf("failed to update Azure secret: %w", err)
	}

	return nil
}

// Delete deletes a secret or a specific version
func (a *AzureKeyVault) Delete(namespace string, name string, version string) error {
	if version != "" {
		return fmt.Errorf("deleting specific versions is not supported in Azure Key Vault")
	}

	// Delete the secret
	_, err := a.client.DeleteSecret(a.ctx, name, nil)
	if err != nil {
		return fmt.Errorf("failed to delete Azure secret: %w", err)
	}

	return nil
}

// getSecretVersions gets all versions of a secret
func (a *AzureKeyVault) getSecretVersions(name string) ([]string, string, error) {
	var versions []string
	var latestVersion string

	pager := a.client.NewListSecretVersionsPager(name, nil)

	// Get the latest version first (will be the first in the list)
	firstIteration := true

	for pager.More() {
		page, err := pager.NextPage(a.ctx)
		if err != nil {
			return nil, "", fmt.Errorf("failed to list versions for Azure secret %s: %w", name, err)
		}

		for _, version := range page.Value {
			if version.ID != nil {
				versionID := extractVersionFromID(string(*version.ID))
				versions = append(versions, versionID)

				// First version in the list is considered the latest
				if firstIteration && latestVersion == "" {
					latestVersion = versionID
					firstIteration = false
				}
			}
		}
	}

	return versions, latestVersion, nil
}
