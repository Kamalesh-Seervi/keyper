package providers

import (
	"keyper/pkg/aws"
	"keyper/pkg/common"
)

// NewAWSSecretManager creates a new AWS Secrets Manager instance
func NewAWSSecretManager() common.SecretManager {
	return aws.NewAWSSecretManager()
}
