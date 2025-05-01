package providers

import (
	"keyper/pkg/common"
	"keyper/pkg/oracle"
)

// NewOracleVault creates a new Oracle Cloud Vault instance
func NewOracleVault() common.SecretManager {
	return oracle.NewOracleVault()
}
