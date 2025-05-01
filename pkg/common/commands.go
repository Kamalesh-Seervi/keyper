package common

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// GetCommands returns all available commands for the CLI tool
func GetCommands() []*cobra.Command {
	var commands []*cobra.Command

	// Add provider-agnostic commands
	commands = append(commands,
		getListCommand(),
		getGetCommand(),
		getCreateCommand(),
		getUpdateCommand(),
		getDeleteCommand(),
	)

	return commands
}

// getListCommand creates the command for listing secrets
func getListCommand() *cobra.Command {
	var provider, namespace string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all secrets for a given cloud provider",
		Long:  `List all secrets stored in the specified cloud provider. Optionally filter by namespace/path.`,
		Run: func(cmd *cobra.Command, args []string) {
			manager := GetSecretManager(provider)
			if manager == nil {
				fmt.Println("Error: Invalid provider specified")
				os.Exit(1)
			}

			secrets, err := manager.List(namespace)
			if err != nil {
				fmt.Printf("Error listing secrets: %v\n", err)
				os.Exit(1)
			}

			displaySecrets(secrets)
		},
	}

	cmd.Flags().StringVarP(&provider, "provider", "p", "", "Cloud provider (aws, gcp, azure, oracle)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace/path for the secrets")
	cmd.MarkFlagRequired("provider")

	return cmd
}

// getGetCommand creates the command for retrieving a secret
func getGetCommand() *cobra.Command {
	var provider, namespace, name, version string

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a secret value",
		Long:  `Retrieve the value of a secret from the specified cloud provider.`,
		Run: func(cmd *cobra.Command, args []string) {
			manager := GetSecretManager(provider)
			if manager == nil {
				fmt.Println("Error: Invalid provider specified")
				os.Exit(1)
			}

			secretValue, err := manager.Get(namespace, name, version)
			if err != nil {
				fmt.Printf("Error getting secret: %v\n", err)
				os.Exit(1)
			}

			displaySecretValue(secretValue)
		},
	}

	cmd.Flags().StringVarP(&provider, "provider", "p", "", "Cloud provider (aws, gcp, azure, oracle)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace/path for the secret")
	cmd.Flags().StringVarP(&name, "name", "m", "", "Name of the secret")
	cmd.Flags().StringVarP(&version, "version", "v", "", "Version of the secret (optional)")
	cmd.MarkFlagRequired("provider")
	cmd.MarkFlagRequired("name")

	return cmd
}

// getCreateCommand creates the command for adding a new secret
func getCreateCommand() *cobra.Command {
	var provider, namespace, name, value, labelsStr string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new secret",
		Long:  `Add a new secret to the specified cloud provider.`,
		Run: func(cmd *cobra.Command, args []string) {
			manager := GetSecretManager(provider)
			if manager == nil {
				fmt.Println("Error: Invalid provider specified")
				os.Exit(1)
			}

			labels := parseLabels(labelsStr)

			err := manager.Create(namespace, name, value, labels)
			if err != nil {
				fmt.Printf("Error creating secret: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Secret '%s' created successfully in %s\n", name, provider)
		},
	}

	cmd.Flags().StringVarP(&provider, "provider", "p", "", "Cloud provider (aws, gcp, azure, oracle)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace/path for the secret")
	cmd.Flags().StringVarP(&name, "name", "m", "", "Name of the secret")
	cmd.Flags().StringVarP(&value, "value", "v", "", "Value of the secret")
	cmd.Flags().StringVarP(&labelsStr, "labels", "l", "", "Labels for the secret (comma-separated key=value pairs)")
	cmd.MarkFlagRequired("provider")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("value")

	return cmd
}

// getUpdateCommand creates the command for updating a secret
func getUpdateCommand() *cobra.Command {
	var provider, namespace, name, value, labelsStr string

	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update an existing secret",
		Long:  `Update a secret in the specified cloud provider, creating a new version.`,
		Run: func(cmd *cobra.Command, args []string) {
			manager := GetSecretManager(provider)
			if manager == nil {
				fmt.Println("Error: Invalid provider specified")
				os.Exit(1)
			}

			labels := parseLabels(labelsStr)

			err := manager.Update(namespace, name, value, labels)
			if err != nil {
				fmt.Printf("Error updating secret: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Secret '%s' updated successfully in %s\n", name, provider)
		},
	}

	cmd.Flags().StringVarP(&provider, "provider", "p", "", "Cloud provider (aws, gcp, azure, oracle)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace/path for the secret")
	cmd.Flags().StringVarP(&name, "name", "m", "", "Name of the secret")
	cmd.Flags().StringVarP(&value, "value", "v", "", "New value of the secret")
	cmd.Flags().StringVarP(&labelsStr, "labels", "l", "", "Labels for the secret (comma-separated key=value pairs)")
	cmd.MarkFlagRequired("provider")
	cmd.MarkFlagRequired("name")
	cmd.MarkFlagRequired("value")

	return cmd
}

// getDeleteCommand creates the command for deleting a secret
func getDeleteCommand() *cobra.Command {
	var provider, namespace, name, version string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete a secret or version",
		Long:  `Delete a secret or specific version from the specified cloud provider.`,
		Run: func(cmd *cobra.Command, args []string) {
			manager := GetSecretManager(provider)
			if manager == nil {
				fmt.Println("Error: Invalid provider specified")
				os.Exit(1)
			}

			err := manager.Delete(namespace, name, version)
			if err != nil {
				fmt.Printf("Error deleting secret: %v\n", err)
				os.Exit(1)
			}

			if version == "" {
				fmt.Printf("Secret '%s' deleted successfully from %s\n", name, provider)
			} else {
				fmt.Printf("Version '%s' of secret '%s' deleted successfully from %s\n", version, name, provider)
			}
		},
	}

	cmd.Flags().StringVarP(&provider, "provider", "p", "", "Cloud provider (aws, gcp, azure, oracle)")
	cmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace/path for the secret")
	cmd.Flags().StringVarP(&name, "name", "m", "", "Name of the secret")
	cmd.Flags().StringVarP(&version, "version", "v", "", "Version of the secret (optional)")
	cmd.MarkFlagRequired("provider")
	cmd.MarkFlagRequired("name")

	return cmd
}

// Helper functions for displaying results
func displaySecrets(secrets []Secret) {
	if len(secrets) == 0 {
		fmt.Println("No secrets found")
		return
	}

	fmt.Println("PROVIDER\tNAMESPACE\tNAME\tVERSIONS\tLATEST\tUPDATED")
	for _, s := range secrets {
		fmt.Printf("%s\t%s\t%s\t%d\t%s\t%s\n", s.Provider, s.Namespace, s.Name, len(s.Versions), s.LatestVersion, s.Updated)
	}
}

func displaySecretValue(secret *SecretValue) {
	if secret == nil {
		fmt.Println("Secret not found")
		return
	}

	fmt.Printf("Name: %s\n", secret.Name)
	fmt.Printf("Namespace: %s\n", secret.Namespace)
	fmt.Printf("Provider: %s\n", secret.Provider)
	fmt.Printf("Version: %s\n", secret.Version)
	fmt.Printf("Value: %s\n", secret.Value)

	if len(secret.Labels) > 0 {
		fmt.Println("Labels:")
		for k, v := range secret.Labels {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}
}

// parseLabels converts a comma-separated key=value string into a map
func parseLabels(labelsStr string) map[string]string {
	labels := make(map[string]string)

	if labelsStr == "" {
		return labels
	}

	pairs := strings.Split(labelsStr, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			labels[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return labels
}
