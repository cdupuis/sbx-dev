// Command gen-catalog regenerates the sbx command catalog that sbx-dev embeds,
// from the CLI reference sbx publishes under docs/yml.
//
// Run it against a checkout of sbx after upgrading the host's sbx, so that
// authorization resolves an argv the way the installed CLI does:
//
//	go run ./cmd/gen-catalog --docs ../sandboxes/docs/yml
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cdupuis/sbx-dev/internal/catalog"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gen-catalog: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		docs    = flag.String("docs", "", "directory holding sbx's generated CLI reference (docs/yml)")
		out     = flag.String("out", filepath.Join("internal", "catalog", "catalog.json"), "file to write")
		sbxPath = flag.String("sbx", "sbx", "sbx binary to read the version from")
		version = flag.String("sbx-version", "", "record this version instead of asking the sbx binary")
	)
	flag.Parse()

	if *docs == "" {
		flag.Usage()
		return fmt.Errorf("--docs is required")
	}

	recorded := *version
	if recorded == "" {
		recorded = readVersion(*sbxPath)
	}

	cat, err := catalog.FromDocs(os.DirFS(*docs), recorded)
	if err != nil {
		return err
	}

	encoded, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(encoded, '\n'), 0o644); err != nil {
		return err
	}

	fmt.Printf("wrote %s: %d commands from sbx %s\n", *out, len(cat.Commands), displayVersion(recorded))
	return nil
}

// readVersion returns the installed sbx's version, or an empty string when it
// cannot be determined. A missing version only costs a diagnostic, so it is not
// worth failing the generation over.
func readVersion(sbxPath string) string {
	output, err := exec.Command(sbxPath, "version").Output()
	if err != nil {
		return ""
	}
	_, version, found := strings.Cut(string(output), ":")
	if !found {
		return ""
	}
	fields := strings.Fields(version)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func displayVersion(version string) string {
	if version == "" {
		return "(unknown version)"
	}
	return version
}
