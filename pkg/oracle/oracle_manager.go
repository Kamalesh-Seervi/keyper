package oracle

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	sdkCommon "github.com/oracle/oci-go-sdk/v65/common"
	sdkSecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	sdkVault "github.com/oracle/oci-go-sdk/v65/vault"

	"keyper/pkg/common"
)

// OracleVault implements the common.SecretManager interface for OCI Vault
type OracleVault struct {
	vaultClient   sdkVault.VaultsClient
	secretClient  sdkSecrets.SecretsClient
	ctx           context.Context
	compartmentID string
}

// NewOracleVault creates a new Oracle Cloud Vault instance
func NewOracleVault() common.SecretManager {
	ctx := context.Background()

	// Set up OCI configuration provider
	configProvider := sdkCommon.DefaultConfigProvider()

	// Create vault client
	vaultClient, err := sdkVault.NewVaultsClientWithConfigurationProvider(configProvider)
	if err != nil {
		fmt.Printf("Failed to create OCI Vault client: %v\n", err)
		return nil
	}

	// Create secrets client
	secretClient, err := sdkSecrets.NewSecretsClientWithConfigurationProvider(configProvider)
	if err != nil {
		fmt.Printf("Failed to create OCI Secrets client: %v\n", err)
		return nil
	}

	// Try to get default compartment ID from environment or configuration
	compartmentID := getDefaultCompartmentID()

	return &OracleVault{
		vaultClient:   vaultClient,
		secretClient:  secretClient,
		ctx:           ctx,
		compartmentID: compartmentID,
	}
}

// List returns all secrets in the given namespace/path
func (o *OracleVault) List(namespace string) ([]common.Secret, error) {
	var secrets []common.Secret

	// In OCI, namespace represents the compartment ID
	compartmentID := namespace
	if compartmentID == "" {
		compartmentID = o.compartmentID
		if compartmentID == "" {
			return nil, fmt.Errorf("missing compartment ID")
		}
	}

	// Use a single vault from environment
	vaultID := os.Getenv("OCI_VAULT_ID")
	if vaultID == "" {
		return nil, fmt.Errorf("OCI_VAULT_ID environment variable not set")
	}
	// List secrets in the vault
	secretsReq := sdkVault.ListSecretsRequest{
		CompartmentId: &compartmentID,
		VaultId:       &vaultID,
		Limit:         sdkCommon.Int(100),
	}
	secretsResp, err := o.vaultClient.ListSecrets(o.ctx, secretsReq)
	if err != nil {
		return nil, fmt.Errorf("failed to list OCI secrets: %w", err)
	}

	for _, s := range secretsResp.Items {
		if s.SecretName == nil {
			continue
		}

		// Extract secret metadata
		name := *s.SecretName
		if s.Id == nil {
			continue
		}

		// Get versions for this secret (OCI doesn't provide a direct API for listing versions)
		// Instead, we'll just indicate the current version
		versions := []string{"current"}
		latestVersion := "current"

		// Extract tags/labels
		labels := make(map[string]string)
		if s.FreeformTags != nil {
			for k, v := range s.FreeformTags {
				labels[k] = v
			}
		}

		// Format creation and update times
		created := ""
		if s.TimeCreated != nil {
			created = s.TimeCreated.String()
		}

		updated := ""
		// OCI doesn't have an explicit "updated" time at the secret level,
		// so we'll use TimeCreated as a fallback
		if s.TimeCreated != nil {
			updated = s.TimeCreated.String()
		}

		secrets = append(secrets, common.Secret{
			Name:          name,
			Namespace:     compartmentID,
			Provider:      "oracle",
			Versions:      versions,
			LatestVersion: latestVersion,
			Labels:        labels,
			Created:       created,
			Updated:       updated,
		})
	}

	return secrets, nil
}

// Get retrieves a specific secret value
func (o *OracleVault) Get(namespace string, name string, version string) (*common.SecretValue, error) {
	// In OCI, namespace represents the compartment ID
	compartmentID := namespace
	if compartmentID == "" {
		compartmentID = o.compartmentID
		if compartmentID == "" {
			return nil, fmt.Errorf("missing compartment ID")
		}
	}

	// Find the secret by name
	secretID, err := o.findSecretIDByName(compartmentID, name)
	if err != nil {
		return nil, err
	}

	// Version is not directly supported in OCI Secrets - there's only the current version
	if version != "" && version != "current" {
		return nil, fmt.Errorf("OCI only supports 'current' as the version identifier")
	}

	// Get the secret bundle
	req := sdkSecrets.GetSecretBundleRequest{
		SecretId: secretID,
		Stage:    sdkSecrets.GetSecretBundleStageLatest,
	}

	resp, err := o.secretClient.GetSecretBundle(o.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get OCI secret: %w", err)
	}

	// Extract secret value
	value := ""
	if resp.SecretBundleContent != nil {
		switch content := resp.SecretBundleContent.(type) {
		case sdkSecrets.Base64SecretBundleContentDetails:
			// Decode base64 content
			if content.Content != nil {
				decodedValue, err := base64.StdEncoding.DecodeString(*content.Content)
				if err == nil {
					value = string(decodedValue)
				}
			}
		}
	}

	// Extract tags/labels from secret bundle metadata
	labels := make(map[string]string)
	if resp.SecretBundle.Metadata != nil {
		for k, v := range resp.SecretBundle.Metadata {
			labels[k] = fmt.Sprintf("%v", v)
		}
	}

	// Format creation time
	created := ""
	if resp.SecretBundle.TimeCreated != nil {
		created = resp.SecretBundle.TimeCreated.String()
	}

	// Determine version number
	versionNumber := ""
	if resp.SecretBundle.VersionNumber != nil {
		versionNumber = fmt.Sprintf("%v", *resp.SecretBundle.VersionNumber)
	}

	return &common.SecretValue{
		Name:      name,
		Namespace: compartmentID,
		Provider:  "oracle",
		Version:   versionNumber,
		Value:     value,
		Labels:    labels,
		Created:   created,
	}, nil
}

// Create adds a new secret
func (o *OracleVault) Create(namespace string, name string, value string, labels map[string]string) error {
	// In OCI, namespace represents the compartment ID
	compartmentID := namespace
	if compartmentID == "" {
		compartmentID = o.compartmentID
		if compartmentID == "" {
			return fmt.Errorf("missing compartment ID")
		}
	}

	// First, we need a vault to store the secret in
	vaultID, err := o.getDefaultVaultID(compartmentID)
	if err != nil {
		return err
	}

	// Get default key ID for encryption
	keyID, err := o.getDefaultEncryptionKeyID(compartmentID, vaultID)
	if err != nil {
		return err
	}

	// Convert labels to OCI freeform tags
	freeformTags := make(map[string]string)
	for k, v := range labels {
		freeformTags[k] = v
	}

	encodedValue := base64.StdEncoding.EncodeToString([]byte(value))

	// Create a secret
	secretDetails := sdkVault.CreateSecretDetails{
		CompartmentId: &compartmentID,
		SecretContent: &sdkVault.Base64SecretContentDetails{
			Content: &encodedValue,
		},
		SecretName:   &name,
		VaultId:      &vaultID,
		KeyId:        &keyID,
		FreeformTags: freeformTags,
	}

	req := sdkVault.CreateSecretRequest{
		CreateSecretDetails: secretDetails,
	}

	_, err = o.vaultClient.CreateSecret(o.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create OCI secret: %w", err)
	}

	return nil
}

// Update modifies an existing secret value, creating a new version
func (o *OracleVault) Update(namespace string, name string, value string, labels map[string]string) error {
	// In OCI, namespace represents the compartment ID
	compartmentID := namespace
	if compartmentID == "" {
		compartmentID = o.compartmentID
		if compartmentID == "" {
			return fmt.Errorf("missing compartment ID")
		}
	}

	// Find the secret by name
	secretID, err := o.findSecretIDByName(compartmentID, name)
	if err != nil {
		return err
	}

	// Convert labels to OCI freeform tags
	freeformTags := make(map[string]string)
	for k, v := range labels {
		freeformTags[k] = v
	}

	encodedValue := base64.StdEncoding.EncodeToString([]byte(value))

	// Update the secret
	updateDetails := sdkVault.UpdateSecretDetails{
		SecretContent: &sdkVault.Base64SecretContentDetails{
			Content: &encodedValue,
		},
		FreeformTags: freeformTags,
	}

	req := sdkVault.UpdateSecretRequest{
		SecretId:            secretID,
		UpdateSecretDetails: updateDetails,
	}

	_, err = o.vaultClient.UpdateSecret(o.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to update OCI secret: %w", err)
	}

	return nil
}

// Delete removes a secret
func (o *OracleVault) Delete(namespace string, name string, version string) error {
	// In OCI, namespace represents the compartment ID
	compartmentID := namespace
	if compartmentID == "" {
		compartmentID = o.compartmentID
		if compartmentID == "" {
			return fmt.Errorf("missing compartment ID")
		}
	}

	// Find the secret by name
	secretID, err := o.findSecretIDByName(compartmentID, name)
	if err != nil {
		return err
	}

	// Version is not directly supported for deletion in OCI Secrets
	// Specifying a version will result in an error
	if version != "" {
		return fmt.Errorf("OCI does not support deleting specific secret versions")
	}

	// Schedule the secret for deletion
	deleteTime := time.Now().Add(24 * time.Hour)
	sdkTime := &sdkCommon.SDKTime{Time: deleteTime}
	deleteDetails := sdkVault.ScheduleSecretDeletionDetails{
		TimeOfDeletion: sdkTime,
	}
	req := sdkVault.ScheduleSecretDeletionRequest{
		SecretId:                      secretID,
		ScheduleSecretDeletionDetails: deleteDetails,
	}
	_, err = o.vaultClient.ScheduleSecretDeletion(o.ctx, req)
	if err != nil {
		return fmt.Errorf("failed to schedule OCI secret deletion: %w", err)
	}

	return nil
}

// Helper functions

// findSecretIDByName finds a secret's ID by its name in a compartment
func (o *OracleVault) findSecretIDByName(compartmentID, name string) (*string, error) {
	// Use vault from env
	vaultID := os.Getenv("OCI_VAULT_ID")
	if vaultID == "" {
		return nil, fmt.Errorf("OCI_VAULT_ID environment variable not set")
	}
	// Use GetSecretBundleByName to find secret
	req := sdkSecrets.GetSecretBundleByNameRequest{
		VaultId:    &vaultID,
		SecretName: &name,
	}
	resp, err := o.secretClient.GetSecretBundleByName(o.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get OCI secret bundle by name: %w", err)
	}
	if resp.SecretBundle.SecretId == nil {
		return nil, fmt.Errorf("secret '%s' not found in vault '%s'", name, vaultID)
	}
	return resp.SecretBundle.SecretId, nil
}

// getDefaultVaultID returns the ID of a vault to use for new secrets
func (o *OracleVault) getDefaultVaultID(compartmentID string) (string, error) {
	// This is a simplified implementation
	// In a real application, you would list vaults in the compartment and select an appropriate one
	// For this implementation, we'll return a dummy value
	return "ocid1.vault.oc1..dummyvaultid", nil
}

// getDefaultEncryptionKeyID returns the ID of a key to use for encryption
func (o *OracleVault) getDefaultEncryptionKeyID(compartmentID, vaultID string) (string, error) {
	// This is a simplified implementation
	// In a real application, you would list keys in the vault and select an appropriate one
	// For this implementation, we'll return a dummy value
	return "ocid1.key.oc1.dummy-key-id", nil
}

// getDefaultCompartmentID attempts to get the default OCI compartment ID
func getDefaultCompartmentID() string {
	// This is a simplified implementation
	// In a real application, you would retrieve this from configuration or environment
	return "ocid1.compartment.oc1.default"
}
