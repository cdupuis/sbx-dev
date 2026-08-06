// Package catalog describes the sbx command tree: which commands exist, which
// flags they take, whether each flag consumes the next argument, and what the
// positional arguments mean.
//
// Authorization needs this description because a decision about an argv is only
// as good as the parse behind it. Without flag arity there is no way to tell the
// value of "--sandbox other" from a positional argument, and a policy that
// guesses can be steered by the caller that supplies the argv. The catalog is
// generated from sbx's own published CLI reference and embedded here, so a
// server resolves an argv the way sbx will, without linking against it.
package catalog

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

// Kind classifies what a positional argument denotes, which is what policy
// reasons about: a sandbox to act on, a host path to reach, an opaque command to
// run, or an image-like reference to pull.
type Kind string

const (
	KindSandbox   Kind = "sandbox"
	KindPath      Kind = "path"
	KindCommand   Kind = "command"
	KindReference Kind = "reference"
	KindNetwork   Kind = "network"
	KindOther     Kind = "other"
)

//go:embed catalog.json
var embedded embed.FS

// Catalog is a snapshot of one sbx version's command tree.
type Catalog struct {
	// SbxVersion is the sbx build the snapshot was taken from. A server logs it
	// so a command that resolves differently than expected can be traced to a
	// stale catalog.
	SbxVersion string     `json:"sbxVersion,omitempty"`
	Commands   []*Command `json:"commands"`

	byPath map[string]*Command
}

// Command is one runnable or grouping node of the command tree.
type Command struct {
	// Path is the command's words after "sbx", so ["policy", "allow",
	// "network"]. It is empty for the root command.
	Path []string `json:"path"`
	// HasSubcommands reports whether other commands extend this path. Such a
	// command may still be runnable in its own right, as "sbx create" is.
	HasSubcommands bool `json:"hasSubcommands,omitempty"`
	// PassThrough reports that everything after a bare "--" belongs to another
	// program and is opaque to sbx.
	PassThrough bool `json:"passThrough,omitempty"`
	// StopFlagsAtFirstPositional reports a command that stops reading its own
	// flags once a positional argument appears, so that "sbx exec box ls -la"
	// gives -la to ls rather than to sbx. Resolution has to know, or it would
	// read the inner command's flags as sbx's own.
	StopFlagsAtFirstPositional bool         `json:"stopFlagsAtFirstPositional,omitempty"`
	Flags                      []Flag       `json:"flags,omitempty"`
	Positionals                []Positional `json:"positionals,omitempty"`
}

// Name renders the command the way a person writes it.
func (c *Command) Name() string {
	return strings.TrimSpace("sbx " + strings.Join(c.Path, " "))
}

// Flag is one option a command accepts.
type Flag struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	// TakesValue reports that the flag consumes a value. It decides whether the
	// token after "--sandbox" is that flag's value or a positional argument,
	// which is the difference between reading an argv correctly and reading the
	// caller's preferred interpretation of it.
	TakesValue bool `json:"takesValue,omitempty"`
	// Repeatable reports a flag that accumulates, so later uses add to rather
	// than replace earlier ones.
	Repeatable bool `json:"repeatable,omitempty"`
}

// Positional is one positional slot in a command's usage.
type Positional struct {
	// Name is the slot's name from sbx's usage line, normalised to upper case
	// with underscores.
	Name string `json:"name"`
	Kind Kind   `json:"kind"`
	// Optional reports a slot sbx allows to be absent.
	Optional bool `json:"optional,omitempty"`
	// Variadic reports a slot that absorbs every remaining argument.
	Variadic bool `json:"variadic,omitempty"`
	// Choices lists the literal values the usage line spells out, as
	// "<allow-all|balanced|deny-all>" does. It is empty when the slot is free
	// text.
	Choices []string `json:"choices,omitempty"`
}

// Embedded returns the catalog generated at build time.
func Embedded() (*Catalog, error) {
	raw, err := embedded.ReadFile("catalog.json")
	if err != nil {
		return nil, fmt.Errorf("read embedded catalog: %w", err)
	}
	return Load(raw)
}

// Load decodes a catalog and indexes it for lookup.
func Load(raw []byte) (*Catalog, error) {
	var cat Catalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return nil, fmt.Errorf("decode catalog: %w", err)
	}
	if len(cat.Commands) == 0 {
		return nil, fmt.Errorf("catalog describes no commands")
	}
	cat.index()
	return &cat, nil
}

func (c *Catalog) index() {
	c.byPath = make(map[string]*Command, len(c.Commands))
	for _, cmd := range c.Commands {
		c.byPath[key(cmd.Path)] = cmd
	}
}

// Lookup returns the command at an exact path.
func (c *Catalog) Lookup(path []string) (*Command, bool) {
	if c.byPath == nil {
		c.index()
	}
	cmd, ok := c.byPath[key(path)]
	return cmd, ok
}

// LongestPrefix returns the deepest command whose path prefixes words, and how
// many words it consumed. It is how resolution finds the command in an argv
// whose remaining words are arguments rather than subcommands.
func (c *Catalog) LongestPrefix(words []string) (*Command, int) {
	if c.byPath == nil {
		c.index()
	}
	best := c.byPath[""]
	bestLen := 0
	for i := 1; i <= len(words); i++ {
		cmd, ok := c.byPath[key(words[:i])]
		if !ok {
			break
		}
		best, bestLen = cmd, i
	}
	return best, bestLen
}

func key(path []string) string { return strings.Join(path, " ") }
