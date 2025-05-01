package common

// SecretManagerFactory is a function type for creating SecretManager instances
type SecretManagerFactory func(provider string) SecretManager

// secretManagerFactory holds the factory function
var secretManagerFactory SecretManagerFactory

// RegisterSecretManagerFactory registers a factory function for creating SecretManager instances
func RegisterSecretManagerFactory(factory SecretManagerFactory) {
	secretManagerFactory = factory
}

// GetSecretManager returns a SecretManager for the specified provider
func GetSecretManager(provider string) SecretManager {
	if secretManagerFactory == nil {
		return nil
	}
	return secretManagerFactory(provider)
}
