package providers

import (
	"keyper/pkg/azure"
	"keyper/pkg/common"
)

// NewAzureKeyVault creates a new Azure Key Vault instance
func NewAzureKeyVault() common.SecretManager {
	return azure.NewAzureKeyVault()
}
