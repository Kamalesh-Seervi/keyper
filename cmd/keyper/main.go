package main

import (
	"fmt"
	"os"

	"keyper/pkg/common"
	_ "keyper/pkg/providers" // Import for side effects (init function)

	"github.com/spf13/cobra"
)

func main() {
	// Create root command
	rootCmd := &cobra.Command{
		Use:   "keyper",
		Short: "Keyper - Multi-cloud secret management CLI tool",
		Long: `Keyper is a developer-friendly CLI tool for managing secrets across
multiple cloud providers including AWS, GCP, Azure, and Oracle.
No need to access cloud UIs for secret management operations.`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	// Add commands
	rootCmd.AddCommand(common.GetCommands()...)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
