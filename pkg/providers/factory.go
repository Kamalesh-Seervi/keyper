package providers

import (
	"strings"

	"keyper/pkg/common"
)

// init registers the secret manager factory with the common package
func init() {
	common.RegisterSecretManagerFactory(GetSecretManager)
}

// GetSecretManager returns the appropriate secret manager implementation
func GetSecretManager(provider string) common.SecretManager {
	switch strings.ToLower(provider) {
	case "aws":
		return NewAWSSecretManager()
	case "gcp":
		return NewGCPSecretManager()
	case "azure":
		return NewAzureKeyVault()
	case "oracle":
		return NewOracleVault()
	default:
		return nil
	}
}
