package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newDockerCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "docker IMAGE",
		Short: "Scan Docker images for secrets",
		Long: `Scan Docker images for secrets in container layers.

This command scans Docker images by:
  1. Pulling the image (if not local)
  2. Extracting each layer
  3. Scanning for secrets in configuration files

Example:
  secretscanner docker my-app:latest
  secretscanner docker python:3.11-slim
  
Note: Requires Docker daemon access. Docker scanning is available
in v1.0 as filesystem scanning (saved images). Live Docker daemon
integration coming in v1.1.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			imageName := args[0]
			
			fmt.Printf("Scanning Docker image: %s\n", imageName)
			fmt.Println()
			fmt.Println("Docker daemon integration is available in v1.1.")
			fmt.Println()
			fmt.Println("Current alternatives:")
			fmt.Println("  1. Save image: docker save IMAGE > image.tar")
			fmt.Println("  2. Scan tarball: secretscanner filesystem --path image.tar")
			fmt.Println("  3. Or extract and scan:")
			fmt.Println("     docker export CONTAINER > filesystem.tar")
			fmt.Println("     tar -xzf filesystem.tar -c extracted/")
			fmt.Println("     secretscanner scan extracted/")
			
			return fmt.Errorf("docker daemon access not available in v1.0")
		},
	}
}
