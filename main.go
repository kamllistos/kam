// Command kam explains what IAM access a Terraform plan grants before you apply it.
package main

import (
	"os"

	"github.com/kamllistos/kam/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
