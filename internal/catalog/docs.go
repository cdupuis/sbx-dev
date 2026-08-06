package catalog

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// FromDocs builds a catalog from sbx's generated CLI reference, the same YAML
// tree Docker Docs consumes. It is the input of choice because sbx maintains it
// as a release artifact, so the description tracks the CLI without this project
// linking against sbx's internals.
func FromDocs(fsys fs.FS, sbxVersion string) (*Catalog, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no CLI reference files found")
	}
	sort.Strings(names)

	docs := make([]docFile, 0, len(names))
	paths := make(map[string]bool, len(names))
	for _, name := range names {
		doc, err := readDoc(fsys, name)
		if err != nil {
			return nil, err
		}
		docs = append(docs, doc)
		paths[key(doc.path())] = true
	}

	cat := &Catalog{SbxVersion: sbxVersion, Commands: make([]*Command, 0, len(docs))}
	for _, doc := range docs {
		cmd := &Command{
			Path:                       doc.path(),
			HasSubcommands:             hasSubcommands(paths, doc.path()),
			StopFlagsAtFirstPositional: stopFlagsAtFirstPositional[key(doc.path())],
			Flags:                      doc.flags(),
		}
		cmd.Positionals, cmd.PassThrough = parseUsage(doc.Usage, doc.Name, cmd.Path, cmd.HasSubcommands)
		cat.Commands = append(cat.Commands, cmd)
	}
	cat.index()
	return cat, nil
}

func readDoc(fsys fs.FS, name string) (docFile, error) {
	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		return docFile{}, err
	}
	var doc docFile
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return docFile{}, fmt.Errorf("parse %s: %w", path.Base(name), err)
	}
	if doc.Name == "" {
		return docFile{}, fmt.Errorf("parse %s: no command name", path.Base(name))
	}
	return doc, nil
}

// docFile is the subset of a generated reference file this package needs.
type docFile struct {
	Name      string      `yaml:"name"`
	Usage     string      `yaml:"usage"`
	Options   []docOption `yaml:"options"`
	Inherited []docOption `yaml:"inherited_options"`
}

type docOption struct {
	Name         string `yaml:"name"`
	Shorthand    string `yaml:"shorthand"`
	DefaultValue string `yaml:"default_value"`
}

// path returns the command's words after "sbx".
func (d docFile) path() []string {
	words := strings.Fields(d.Name)
	if len(words) <= 1 {
		return nil
	}
	return words[1:]
}

// flags merges a command's own options with the persistent options it inherits,
// because both are accepted on its command line.
func (d docFile) flags() []Flag {
	seen := make(map[string]bool, len(d.Options)+len(d.Inherited))
	flags := make([]Flag, 0, len(d.Options)+len(d.Inherited))
	for _, group := range [][]docOption{d.Options, d.Inherited} {
		for _, opt := range group {
			if opt.Name == "" || seen[opt.Name] {
				continue
			}
			seen[opt.Name] = true
			flags = append(flags, Flag{
				Name:       opt.Name,
				Shorthand:  opt.Shorthand,
				TakesValue: takesValue(opt.DefaultValue),
				Repeatable: opt.DefaultValue == "[]",
			})
		}
	}
	sort.Slice(flags, func(i, j int) bool { return flags[i].Name < flags[j].Name })
	return flags
}

// takesValue infers arity from the printed default. The reference does not state
// a flag's type, but a boolean is the only kind whose default prints as "true"
// or "false", and a boolean is the only kind that does not consume the next
// argument. A wrong guess in either direction leaves an argv that no longer
// matches its usage, which resolution rejects rather than misreads.
func takesValue(defaultValue string) bool {
	return defaultValue != "true" && defaultValue != "false"
}

func hasSubcommands(paths map[string]bool, self []string) bool {
	prefix := key(self)
	for candidate := range paths {
		if candidate == prefix {
			continue
		}
		if prefix == "" || strings.HasPrefix(candidate, prefix+" ") {
			return true
		}
	}
	return false
}

var (
	// passThroughGroup matches the "[-- AGENT_ARGS...]" tail, where the space
	// after "--" distinguishes the argument separator from a flag hint such as
	// "[--sandbox SANDBOX]".
	passThroughGroup = regexp.MustCompile(`\[--\s[^\]]*\]`)
	// flagHintGroup matches usage decorations that name flags rather than
	// positional slots: "[--sandbox SANDBOX]" and "(--url <url> | --command
	// <cmd>)". Flags come from the options list, so these carry no new
	// information and would otherwise be read as positional slots.
	flagHintGroup = regexp.MustCompile(`\[-[^\]]*\]|\([^)]*\)`)
)

// parseUsage reads the positional slots out of a usage line, such as
// "sbx exec [flags] SANDBOX COMMAND [ARG...]".
func parseUsage(usage, name string, path []string, hasSubcommands bool) ([]Positional, bool) {
	remainder := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(usage), name))

	passThrough := passThroughGroup.MatchString(remainder)
	remainder = passThroughGroup.ReplaceAllString(remainder, " ")
	remainder = flagHintGroup.ReplaceAllString(remainder, " ")

	var positionals []Positional
	for _, token := range strings.Fields(remainder) {
		switch {
		case token == "[flags]", token == "[command]":
			continue
		case token == "COMMAND" && hasSubcommands:
			// A group's usage says COMMAND where a subcommand goes. Only a
			// command with no subcommands, like "sbx exec", means a real
			// argument by it.
			continue
		}
		positionals = append(positionals, parsePositional(token, path))
	}
	return positionals, passThrough
}

var decorations = strings.NewReplacer("[", "", "]", "", "<", "", ">", "")

func parsePositional(token string, path []string) Positional {
	pos := Positional{
		Optional: strings.HasPrefix(token, "["),
		Variadic: strings.Contains(token, "..."),
	}

	name := strings.TrimSuffix(decorations.Replace(token), "...")
	if choices := literalChoices(name); len(choices) > 0 {
		pos.Choices = choices
		pos.Name = "CHOICE"
	} else {
		pos.Name = strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	}
	pos.Kind = kindOf(path, pos.Name)
	return pos
}

// literalChoices reads an enumeration such as "allow-all|balanced|deny-all".
// Lower case alternatives are the literal values sbx accepts, while upper case
// ones, as in "TAG|ID", name two kinds of value rather than two values.
func literalChoices(name string) []string {
	if !strings.Contains(name, "|") || name != strings.ToLower(name) {
		return nil
	}
	parts := strings.Split(name, "|")
	for _, part := range parts {
		if part == "" {
			return nil
		}
	}
	return parts
}

// slotKinds gives a slot's name its meaning for policy. It is a curated table
// because the usage line spells out a name, not a type, and the difference
// between a sandbox and a host path is the whole point of authorizing a command.
var slotKinds = map[string]Kind{
	"SANDBOX":    KindSandbox,
	"PATH":       KindPath,
	"DIRECTORY":  KindPath,
	"FILE":       KindPath,
	"SRC":        KindPath,
	"DST":        KindPath,
	"COMMAND":    KindCommand,
	"ARG":        KindCommand,
	"AGENT_ARGS": KindCommand,
	"REFERENCE":  KindReference,
	"TAG":        KindReference,
	"TAG|ID":     KindReference,
	"RESOURCES":  KindNetwork,
}

// slotKindsByCommand resolves slot names that mean different things in different
// commands, keyed by the command path and the slot name. The TARGET of
// "sbx policy check network" is a network endpoint, while the TARGET of
// "sbx daemon log-level set" is a daemon component.
var slotKindsByCommand = map[string]Kind{
	"policy check network TARGET": KindNetwork,
}

// stopFlagsAtFirstPositional lists the commands that hand every argument after
// their first positional to the program they run, rather than reading them as
// their own flags. The published reference states a command's flags but not this
// behaviour, and it has to be curated because reading "sbx exec box ls -la" as
// though -la were one of sbx's flags would resolve a different command line than
// the one that runs.
var stopFlagsAtFirstPositional = map[string]bool{
	"exec": true,
}

func kindOf(path []string, name string) Kind {
	if kind, ok := slotKindsByCommand[key(append(append([]string{}, path...), name))]; ok {
		return kind
	}
	if kind, ok := slotKinds[name]; ok {
		return kind
	}
	return KindOther
}
