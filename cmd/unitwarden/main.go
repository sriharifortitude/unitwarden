// Command unitwarden judges how much a systemd service could do if it were compromised.
package main

import (
	"os"

	"github.com/sriharifortitude/unitwarden/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
