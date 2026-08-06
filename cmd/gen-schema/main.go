// Command gen-schema regenerates the Cedar schema documenting the vocabulary an
// sbx-dev policy is written against.
//
// Usage:
//
//	go run ./cmd/gen-schema
//
// The schema is derived from the embedded command catalog, so regenerate it after
// regenerating the catalog.
package main

import (
	"fmt"
	"os"

	"github.com/cdupuis/sbx-dev/internal/authz"
	"github.com/cdupuis/sbx-dev/internal/catalog"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gen-schema: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cat, err := catalog.Embedded()
	if err != nil {
		return err
	}
	if err := os.WriteFile(authz.SchemaFile, authz.Schema(cat), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s for sbx %s\n", authz.SchemaFile, cat.SbxVersion)
	return nil
}
