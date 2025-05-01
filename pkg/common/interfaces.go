package common

// SecretManager interface defines operations that must be implemented by all cloud providers
type SecretManager interface {
	// List returns all secrets for the cloud provider in a given namespace/path
	List(namespace string) ([]Secret, error)

	// Get retrieves a specific secret value
	Get(namespace string, name string, version string) (*SecretValue, error)

	// Create adds a new secret
	Create(namespace string, name string, value string, labels map[string]string) error

	// Update modifies an existing secret value, creating a new version
	Update(namespace string, name string, value string, labels map[string]string) error

	// Delete removes a secret or a specific version
	Delete(namespace string, name string, version string) error
}

// Secret represents metadata about a secret
type Secret struct {
	Name          string
	Namespace     string
	Provider      string
	Versions      []string
	LatestVersion string
	Labels        map[string]string
	Created       string
	Updated       string
}

// SecretValue represents a secret's value and metadata
type SecretValue struct {
	Name      string
	Namespace string
	Provider  string
	Version   string
	Value     string
	Labels    map[string]string
	Created   string
}
