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

			fmt.Fprintf(cmd.OutOrStdout(), "Scanning Docker image: %s\n", imageName)
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Docker daemon integration is not yet available.")
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Current alternatives:")
			fmt.Fprintln(cmd.OutOrStdout(), "  1. Save image: docker save IMAGE > image.tar")
			fmt.Fprintln(cmd.OutOrStdout(), "  2. Scan tarball: secretscanner scan image.tar")
			fmt.Fprintln(cmd.OutOrStdout(), "  3. Or extract and scan:")
			fmt.Fprintln(cmd.OutOrStdout(), "     docker export CONTAINER > filesystem.tar")
			fmt.Fprintln(cmd.OutOrStdout(), "     tar -xf filesystem.tar")
			fmt.Fprintln(cmd.OutOrStdout(), "     secretscanner scan extracted/")

			return fmt.Errorf("docker daemon scanning not implemented in v1.0; use filesystem scanning on extracted images")
		},
	}
}
