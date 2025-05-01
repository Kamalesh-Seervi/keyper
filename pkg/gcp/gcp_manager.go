package gcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"keyper/pkg/common"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// GCPSecretManager implements the common.SecretManager interface for Google Cloud Secret Manager
type GCPSecretManager struct {
	client *secretmanager.Client
	ctx    context.Context
}

// NewGCPSecretManager creates a new Google Cloud Secret Manager instance
func NewGCPSecretManager() common.SecretManager {
	ctx := context.Background()

	// Create the client using Application Default Credentials
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		fmt.Printf("Failed to create GCP Secret Manager client: %v\n", err)
		return nil
	}

	return &GCPSecretManager{
		client: client,
		ctx:    ctx,
	}
}

// List returns all secrets in the given namespace/path (project)
func (g *GCPSecretManager) List(namespace string) ([]common.Secret, error) {
	var secrets []common.Secret

	// In GCP, namespace represents the project ID
	projectID := namespace
	if projectID == "" {
		// Attempt to get default project from environment or metadata server
		var err error
		projectID, err = getDefaultProjectID()
		if err != nil {
			return nil, fmt.Errorf("failed to determine GCP project ID: %w", err)
		}
	}

	// List all secrets in the project
	parent := fmt.Sprintf("projects/%s", projectID)
	req := &secretmanagerpb.ListSecretsRequest{
		Parent: parent,
	}

	it := g.client.ListSecrets(g.ctx, req)
	for {
		secret, err := it.Next()
		if err != nil {
			// If we've reached the end of the results, break
			if err.Error() == "no more items in iterator" {
				break
			}
			return nil, fmt.Errorf("failed to list GCP secrets: %w", err)
		}

		// Extract secret name from the full resource name
		name := extractSecretName(secret.Name)

		// Get versions for this secret
		versions, latestVersion, err := g.getSecretVersions(secret.Name)
		if err != nil {
			// Log the error but continue with other secrets
			fmt.Printf("Warning: could not fetch versions for secret %s: %v\n", name, err)
		}

		// Parse labels
		labels := make(map[string]string)
		for k, v := range secret.Labels {
			labels[k] = v
		}

		// Format creation and update times
		created := ""
		if secret.CreateTime != nil {
			created = secret.CreateTime.AsTime().Format(time.RFC3339)
		}

		updated := ""
		// GCP Secret Manager doesn't have an explicit "updated" time at the secret level,
		// so we'll use CreateTime as a fallback
		if secret.CreateTime != nil {
			updated = secret.CreateTime.AsTime().Format(time.RFC3339)
		}

		secrets = append(secrets, common.Secret{
			Name:          name,
			Namespace:     projectID,
			Provider:      "gcp",
			Versions:      versions,
			LatestVersion: latestVersion,
			Labels:        labels,
			Created:       created,
			Updated:       updated,
		})
	}

	return secrets, nil
}

// Get retrieves a secret value by name and version
func (g *GCPSecretManager) Get(namespace string, name string, version string) (*common.SecretValue, error) {
	// In GCP, namespace represents the project ID
	projectID := namespace
	if projectID == "" {
		// Attempt to get default project from environment or metadata server
		var err error
		projectID, err = getDefaultProjectID()
		if err != nil {
			return nil, fmt.Errorf("failed to determine GCP project ID: %w", err)
		}
	}

	// Construct the resource name for the secret version
	resourceName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", projectID, name, version)

	// Access the secret version
	result, err := g.client.AccessSecretVersion(g.ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: resourceName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}

	// Extract secret data
	secretData := string(result.Payload.Data)

	// Get secret metadata (the AccessSecretVersion API doesn't return the CreateTime)
	// so we'll retrieve the secret version to get that information
	versionResult, err := g.client.GetSecretVersion(g.ctx, &secretmanagerpb.GetSecretVersionRequest{
		Name: resourceName,
	})

	// Format creation time for display if available
	creationTime := ""
	if err == nil && versionResult != nil && versionResult.CreateTime != nil {
		creationTime = versionResult.CreateTime.AsTime().Format(time.RFC3339)
	}

	// Return the secret value
	return &common.SecretValue{
		Name:      name,
		Namespace: projectID,
		Provider:  "gcp",
		Version:   version,
		Value:     secretData,
		Created:   creationTime,
	}, nil
}

// Create adds a new secret
func (g *GCPSecretManager) Create(namespace string, name string, value string, labels map[string]string) error {
	// In GCP, namespace represents the project ID
	projectID := namespace
	if projectID == "" {
		// Attempt to get default project from environment or metadata server
		var err error
		projectID, err = getDefaultProjectID()
		if err != nil {
			return fmt.Errorf("failed to determine GCP project ID: %w", err)
		}
	}

	// Construct the parent resource name
	parent := fmt.Sprintf("projects/%s", projectID)

	// Create the secret
	createSecretReq := &secretmanagerpb.CreateSecretRequest{
		Parent:   parent,
		SecretId: name,
		Secret: &secretmanagerpb.Secret{
			Labels: labels,
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		},
	}

	secret, err := g.client.CreateSecret(g.ctx, createSecretReq)
	if err != nil {
		return fmt.Errorf("failed to create GCP secret: %w", err)
	}

	// Add the secret version with the value
	addVersionReq := &secretmanagerpb.AddSecretVersionRequest{
		Parent: secret.Name,
		Payload: &secretmanagerpb.SecretPayload{
			Data: []byte(value),
		},
	}

	_, err = g.client.AddSecretVersion(g.ctx, addVersionReq)
	if err != nil {
		return fmt.Errorf("failed to add GCP secret version: %w", err)
	}

	return nil
}

// Update updates an existing secret with a new value
func (g *GCPSecretManager) Update(namespace string, name string, value string, labels map[string]string) error {
	// Determine project ID to use
	projectID := namespace
	if projectID == "" {
		// Attempt to get default project from environment or metadata server
		var err error
		projectID, err = getDefaultProjectID()
		if err != nil {
			return fmt.Errorf("failed to determine GCP project ID: %w", err)
		}
	}

	// First, check if the secret exists
	secretName := fmt.Sprintf("projects/%s/secrets/%s", projectID, name)
	_, err := g.client.GetSecret(g.ctx, &secretmanagerpb.GetSecretRequest{
		Name: secretName,
	})
	if err != nil {
		return fmt.Errorf("secret not found: %w", err)
	}

	// Update the secret's labels if provided
	if labels != nil && len(labels) > 0 {
		// Update the secret with new labels
		updateMask := &fieldmaskpb.FieldMask{
			Paths: []string{"labels"},
		}

		_, err = g.client.UpdateSecret(g.ctx, &secretmanagerpb.UpdateSecretRequest{
			Secret: &secretmanagerpb.Secret{
				Name:   secretName,
				Labels: labels,
			},
			UpdateMask: updateMask,
		})
		if err != nil {
			return fmt.Errorf("failed to update secret labels: %w", err)
		}
	}

	// Add a new secret version with the new value
	_, err = g.client.AddSecretVersion(g.ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent: secretName,
		Payload: &secretmanagerpb.SecretPayload{
			Data: []byte(value),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to add secret version: %w", err)
	}

	return nil
}

// Delete removes a secret or a specific version
func (g *GCPSecretManager) Delete(namespace string, name string, version string) error {
	// In GCP, namespace represents the project ID
	projectID := namespace
	if projectID == "" {
		// Attempt to get default project from environment or metadata server
		var err error
		projectID, err = getDefaultProjectID()
		if err != nil {
			return fmt.Errorf("failed to determine GCP project ID: %w", err)
		}
	}

	// Construct the secret name
	secretName := fmt.Sprintf("projects/%s/secrets/%s", projectID, name)

	if version == "" {
		// Delete the entire secret
		deleteSecretReq := &secretmanagerpb.DeleteSecretRequest{
			Name: secretName,
		}

		err := g.client.DeleteSecret(g.ctx, deleteSecretReq)
		if err != nil {
			return fmt.Errorf("failed to delete GCP secret: %w", err)
		}
	} else {
		// Delete a specific version
		versionName := fmt.Sprintf("%s/versions/%s", secretName, version)

		destroyVersionReq := &secretmanagerpb.DestroySecretVersionRequest{
			Name: versionName,
		}

		_, err := g.client.DestroySecretVersion(g.ctx, destroyVersionReq)
		if err != nil {
			return fmt.Errorf("failed to delete GCP secret version: %w", err)
		}
	}

	return nil
}

// Helper functions

// getSecretVersions returns all versions of a secret
func (g *GCPSecretManager) getSecretVersions(secretName string) ([]string, string, error) {
	listVersionsReq := &secretmanagerpb.ListSecretVersionsRequest{
		Parent: secretName,
	}

	var versions []string
	var latestVersion string

	it := g.client.ListSecretVersions(g.ctx, listVersionsReq)
	for {
		version, err := it.Next()
		if err != nil {
			// If we've reached the end of the results, break
			if err.Error() == "no more items in iterator" {
				break
			}
			return nil, "", fmt.Errorf("failed to list GCP secret versions: %w", err)
		}

		// Only include enabled versions
		if version.State == secretmanagerpb.SecretVersion_ENABLED {
			versionNumber := extractVersionNumber(version.Name)
			versions = append(versions, versionNumber)

			// Check if this is the latest version
			// In GCP, we can identify the latest version as it usually has the highest numeric value
			if latestVersion == "" || versionNumber > latestVersion {
				latestVersion = versionNumber
			}
		}
	}

	return versions, latestVersion, nil
}

// extractSecretName extracts just the secret name from the full resource name
func extractSecretName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 4 {
		return parts[3]
	}
	return fullName
}

// extractVersionNumber extracts just the version number from the full version name
func extractVersionNumber(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 6 {
		return parts[5]
	}
	return fullName
}

// getDefaultProjectID attempts to get the default GCP project ID
func getDefaultProjectID() (string, error) {
	// This is a simplified implementation
	// In a real application, you would use the GCP SDK to retrieve the default project
	// For example, from the GOOGLE_CLOUD_PROJECT environment variable or metadata server
	projectID := "default-project" // Replace with actual implementation
	if projectID == "" {
		return "", fmt.Errorf("could not determine default GCP project ID")
	}
	return projectID, nil
}
