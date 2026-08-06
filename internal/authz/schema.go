package authz

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/cdupuis/sbx-warden/internal/catalog"
)

// SchemaFile is where the generated schema is committed, relative to the module
// root.
const SchemaFile = "policies/sbx.cedarschema"

// Schema renders the Cedar schema for the vocabulary a policy is written
// against: the entity types, every action sbx offers, the capability groups those
// actions belong to, and the context a request carries.
//
// It is generated from the catalog and the group table rather than maintained by
// hand, so it cannot claim an action sbx does not have or omit one it does.
func Schema(cat *catalog.Catalog) []byte {
	var b bytes.Buffer

	b.WriteString(`// The vocabulary an sbx-warden policy is written against.
//
// Generated from the embedded sbx command catalog. Do not edit: run
// "task policy:schema" to regenerate it after the catalog changes.
//
// One part of the request cannot be expressed here. context.flagValues holds the
// value of each flag a command was given, keyed by flag name, and Cedar records
// have fixed attributes — the keys depend on which command ran, so the record
// cannot be typed. Policies may still read it; only this schema is silent about
// it.

namespace SBX {
    // A named group a sandbox belongs to. Membership comes from the policy map,
    // which assigns groups to sandbox names and patterns.
    entity Group;

    // The calling sandbox, and the sandbox a command acts on.
    entity Sandbox in [Group] {
        // The sandbox's name, for patterns: principal.name like "worker-*".
        name: String,
    };

    // The resource for a command that acts on the host rather than on one
    // sandbox, such as "sbx ls" or "sbx daemon status".
    entity Host;

`)

	b.WriteString("    // What the server parsed out of the command line.\n")
	b.WriteString("    type Invocation = {\n")
	for _, attr := range contextAttributes() {
		for _, line := range wrap(attr.doc, 68) {
			fmt.Fprintf(&b, "        // %s\n", line)
		}
		fmt.Fprintf(&b, "        %s: %s,\n", attr.name, attr.cedarType)
	}
	b.WriteString("    };\n\n")

	b.WriteString("    // Capability groups. A policy grants one of these rather than a list of\n")
	b.WriteString("    // command names, so it keeps meaning what it meant as sbx grows.\n")
	for _, group := range AllGroups() {
		fmt.Fprintf(&b, "    action %q;\n", group)
	}

	b.WriteString("\n    // Every command sbx offers. A command in no group can only be granted by\n")
	b.WriteString("    // name, which is why a policy written in groups cannot reach a new one by\n")
	b.WriteString("    // accident.\n")
	for _, path := range commandPaths(cat) {
		fmt.Fprintf(&b, "    action %q", path)
		if groups := Groups(path); len(groups) > 0 {
			quoted := make([]string, len(groups))
			for i, group := range groups {
				quoted[i] = fmt.Sprintf("%q", group)
			}
			fmt.Fprintf(&b, " in [%s]", strings.Join(quoted, ", "))
		}
		b.WriteString(" appliesTo {\n")
		b.WriteString("        principal: [Sandbox],\n")
		b.WriteString("        resource: [Sandbox, Host],\n")
		b.WriteString("        context: Invocation\n")
		b.WriteString("    };\n")
	}

	b.WriteString("}\n")
	return b.Bytes()
}

// contextAttribute documents one context attribute in the schema.
type contextAttribute struct {
	name      string
	cedarType string
	doc       string
}

// contextAttributes describes the context record. It is the one part of the
// schema that is written rather than derived, so it has to be kept beside
// buildContext; the test that renders a real request against it fails if an
// attribute is added there and not here.
func contextAttributes() []contextAttribute {
	return []contextAttribute{
		{"command", "String", `The full command path, so "policy allow network".`},
		{"flags", "Set<String>", "The names of the flags the command was given."},
		{"hostPaths", "Set<String>", "Every host path the command names, made absolute against the server's working directory and cleaned, so \"..\" cannot walk out of a confined tree."},
		{"hostPathsRoot", "String", "The deepest directory containing all of hostPaths. Cedar cannot test every member of a set, so confinement is expressed against this: it lies under a prefix exactly when all the paths do."},
		{"hostPathsUnderWorkdir", "Bool", "Whether every host path lies under the directory sbx-warden runs in. True when the command names no host path. This is the portable form of confinement, for a policy that should not name a site's directory."},
		{"sandboxPaths", "Set<String>", `Paths inside a sandbox, from the "sandbox:/path" form sbx cp accepts.`},
		{"sandboxes", "Set<String>", "Every sandbox the command names."},
		{"references", "Set<String>", "Image-like references the command names."},
		{"network", "Set<String>", "Network destinations the command names."},
		{"targetsSelf", "Bool", "Whether the command names at least one sandbox and every sandbox it names is the caller. Naming a sibling alongside itself is not \"itself\"."},
		{"targetsHost", "Bool", "Whether the command names no sandbox and so acts on the host."},
		{"forwardsArguments", "Bool", "Whether the command carries arguments for another program, as \"sbx exec\" does. Their content is opaque, so a policy can refuse them but not inspect them."},
	}
}

// wrap breaks text into lines of at most width characters, so a generated
// comment reads as prose rather than one long line.
func wrap(text string, width int) []string {
	var (
		lines []string
		line  string
	)
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) <= width:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// commandPaths lists every runnable command path in the catalog, sorted so the
// generated schema is stable.
func commandPaths(cat *catalog.Catalog) []string {
	paths := make([]string, 0, len(cat.Commands))
	for _, cmd := range cat.Commands {
		if len(cmd.Path) == 0 {
			continue
		}
		paths = append(paths, strings.Join(cmd.Path, " "))
	}
	sort.Strings(paths)
	return paths
}
