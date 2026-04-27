package main

import (
	"context"
	"os"

	"github.com/Alaxay8/dpireverse/cmd"
)

func main() {
	os.Exit(cmd.Execute(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
