package providers

import (
	"keyper/pkg/common"
	"keyper/pkg/gcp"
)

// NewGCPSecretManager creates a new GCP Secret Manager instance
func NewGCPSecretManager() common.SecretManager {
	return gcp.NewGCPSecretManager()
}
