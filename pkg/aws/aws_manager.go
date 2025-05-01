package aws

import (
	"fmt"
	"time"

	"keyper/pkg/common"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

// AWSSecretManager implements the common.SecretManager interface for AWS Secrets Manager
type AWSSecretManager struct {
	client *secretsmanager.SecretsManager
}

// NewAWSSecretManager creates a new AWS Secrets Manager instance
func NewAWSSecretManager() common.SecretManager {
	// Create AWS session using default credential provider chain
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create Secrets Manager client
	client := secretsmanager.New(sess)

	return &AWSSecretManager{
		client: client,
	}
}

// List returns all secrets in the given namespace/path
func (a *AWSSecretManager) List(namespace string) ([]common.Secret, error) {
	var secrets []common.Secret
	var nextToken *string

	for {
		// AWS doesn't support namespaces like other providers, so we'll use filters
		// to simulate namespace support using tag or name prefix filtering
		input := &secretsmanager.ListSecretsInput{
			MaxResults: aws.Int64(100),
			NextToken:  nextToken,
		}

		// If namespace is provided, use it as a filter
		if namespace != "" {
			input.Filters = []*secretsmanager.Filter{
				{
					Key:    aws.String("name"),
					Values: []*string{aws.String(namespace + "*")},
				},
			}
		}

		result, err := a.client.ListSecrets(input)
		if err != nil {
			return nil, fmt.Errorf("failed to list AWS secrets: %w", err)
		}

		for _, secretEntry := range result.SecretList {
			versions, latestVersion, err := a.getSecretVersions(*secretEntry.ARN)
			if err != nil {
				// Log the error but continue with other secrets
				fmt.Printf("Warning: could not fetch versions for secret %s: %v\n", *secretEntry.Name, err)
			}

			// Parse tags into labels
			labels := make(map[string]string)
			for _, tag := range secretEntry.Tags {
				if tag.Key != nil && tag.Value != nil {
					labels[*tag.Key] = *tag.Value
				}
			}

			updated := ""
			if secretEntry.LastChangedDate != nil {
				updated = secretEntry.LastChangedDate.Format(time.RFC3339)
			}

			created := ""
			if secretEntry.CreatedDate != nil {
				created = secretEntry.CreatedDate.Format(time.RFC3339)
			}

			secrets = append(secrets, common.Secret{
				Name:          *secretEntry.Name,
				Namespace:     namespace,
				Provider:      "aws",
				Versions:      versions,
				LatestVersion: latestVersion,
				Labels:        labels,
				Created:       created,
				Updated:       updated,
			})
		}

		// Check if there are more secrets to fetch
		if result.NextToken == nil {
			break
		}

		nextToken = result.NextToken
	}

	return secrets, nil
}

// Get retrieves a specific secret value
func (a *AWSSecretManager) Get(namespace string, name string, version string) (*common.SecretValue, error) {
	// In AWS, construct the full secret name based on namespace if provided
	secretId := name
	if namespace != "" {
		secretId = namespace + "/" + name
	}

	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretId),
	}

	// If version is specified, use it
	if version != "" {
		input.VersionId = aws.String(version)
	} else {
		input.VersionStage = aws.String("AWSCURRENT") // Default to latest version
	}

	result, err := a.client.GetSecretValue(input)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS secret: %w", err)
	}

	// Get the secret's metadata to extract labels (tags)
	metadataInput := &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretId),
	}

	metadata, err := a.client.DescribeSecret(metadataInput)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS secret metadata: %w", err)
	}

	// Parse tags into labels
	labels := make(map[string]string)
	for _, tag := range metadata.Tags {
		if tag.Key != nil && tag.Value != nil {
			labels[*tag.Key] = *tag.Value
		}
	}

	// Get the value (could be either SecretString or SecretBinary)
	value := ""
	if result.SecretString != nil {
		value = *result.SecretString
	} else if result.SecretBinary != nil {
		// For binary secrets, we'd need to handle differently
		value = "[BINARY SECRET - Use AWS SDK to retrieve binary value]"
	}

	created := ""
	if result.CreatedDate != nil {
		created = result.CreatedDate.Format(time.RFC3339)
	}

	return &common.SecretValue{
		Name:      name,
		Namespace: namespace,
		Provider:  "aws",
		Version:   *result.VersionId,
		Value:     value,
		Labels:    labels,
		Created:   created,
	}, nil
}

// Create adds a new secret
func (a *AWSSecretManager) Create(namespace string, name string, value string, labels map[string]string) error {
	// In AWS, construct the full secret name based on namespace if provided
	secretId := name
	if namespace != "" {
		secretId = namespace + "/" + name
	}

	// Convert labels to AWS tags
	var tags []*secretsmanager.Tag
	for k, v := range labels {
		tags = append(tags, &secretsmanager.Tag{
			Key:   aws.String(k),
			Value: aws.String(v),
		})
	}

	// Create the secret
	_, err := a.client.CreateSecret(&secretsmanager.CreateSecretInput{
		Name:         aws.String(secretId),
		SecretString: aws.String(value),
		Tags:         tags,
	})

	if err != nil {
		return fmt.Errorf("failed to create AWS secret: %w", err)
	}

	return nil
}

// Update modifies an existing secret value, creating a new version
func (a *AWSSecretManager) Update(namespace string, name string, value string, labels map[string]string) error {
	// In AWS, construct the full secret name based on namespace if provided
	secretId := name
	if namespace != "" {
		secretId = namespace + "/" + name
	}

	// Update the secret value
	_, err := a.client.PutSecretValue(&secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretId),
		SecretString: aws.String(value),
	})

	if err != nil {
		return fmt.Errorf("failed to update AWS secret value: %w", err)
	}

	// If labels are provided, update them as tags
	if len(labels) > 0 {
		// Convert labels to AWS tags
		var tags []*secretsmanager.Tag
		for k, v := range labels {
			tags = append(tags, &secretsmanager.Tag{
				Key:   aws.String(k),
				Value: aws.String(v),
			})
		}

		_, err = a.client.TagResource(&secretsmanager.TagResourceInput{
			SecretId: aws.String(secretId),
			Tags:     tags,
		})

		if err != nil {
			return fmt.Errorf("failed to update AWS secret tags: %w", err)
		}
	}

	return nil
}

// Delete removes a secret or a specific version
func (a *AWSSecretManager) Delete(namespace string, name string, version string) error {
	// In AWS, construct the full secret name based on namespace if provided
	secretId := name
	if namespace != "" {
		secretId = namespace + "/" + name
	}

	if version == "" {
		// Delete the entire secret
		_, err := a.client.DeleteSecret(&secretsmanager.DeleteSecretInput{
			SecretId:                   aws.String(secretId),
			ForceDeleteWithoutRecovery: aws.Bool(true), // Set to false for recovery window
		})

		if err != nil {
			return fmt.Errorf("failed to delete AWS secret: %w", err)
		}
	} else {
		// Delete a specific version
		_, err := a.client.UpdateSecretVersionStage(&secretsmanager.UpdateSecretVersionStageInput{
			SecretId:            aws.String(secretId),
			VersionStage:        aws.String("AWSCURRENT"),
			RemoveFromVersionId: aws.String(version),
		})

		if err != nil {
			return fmt.Errorf("failed to delete AWS secret version: %w", err)
		}
	}

	return nil
}

// Helper function to get all versions of a secret
func (a *AWSSecretManager) getSecretVersions(secretArn string) ([]string, string, error) {
	input := &secretsmanager.ListSecretVersionIdsInput{
		SecretId: aws.String(secretArn),
	}

	result, err := a.client.ListSecretVersionIds(input)
	if err != nil {
		return nil, "", err
	}

	versions := make([]string, 0, len(result.Versions))
	var latestVersion string

	for _, version := range result.Versions {
		if version.VersionId != nil {
			versions = append(versions, *version.VersionId)

			// Check if this is the current version
			if version.VersionStages != nil {
				for _, stage := range version.VersionStages {
					if stage != nil && *stage == "AWSCURRENT" {
						latestVersion = *version.VersionId
						break
					}
				}
			}
		}
	}

	if latestVersion == "" && len(versions) > 0 {
		latestVersion = versions[len(versions)-1] // Fallback to last version
	}

	return versions, latestVersion, nil
}
