// Package resolve turns an argv into the command, flags and positional
// arguments sbx itself will see.
//
// Authorizing an argv by pattern matching invites the caller to disagree with
// the parse: "--sandbox" followed by a name looks like two positional arguments
// unless something knows the flag consumes one. This package resolves an argv
// against the embedded catalog, following the same rules sbx's flag parser does,
// and refuses anything it cannot resolve exactly. A refusal is the safe answer,
// because an argv nobody can explain is an argv nobody can authorize.
package resolve

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cdupuis/sbx-dev/internal/catalog"
)

// ErrUnresolvable reports an argv that could not be resolved against the
// catalog. Every parse failure wraps it, since the caller's response is always
// the same: refuse to run the command.
var ErrUnresolvable = errors.New("cannot resolve this command line")

// Invocation is an argv resolved into the parts a policy reasons about.
type Invocation struct {
	// Command is the catalog entry the argv names.
	Command *catalog.Command
	// Flags maps each flag's canonical long name to the values given for it.
	// A boolean flag records the value sbx will read, so "-t" appears as
	// "tty": ["true"].
	Flags map[string][]string
	// Slots pairs each positional argument with the slot it filled.
	Slots []Slot
	// PassThrough holds the arguments after a bare "--" for a command that
	// forwards them to another program. They are opaque: sbx does not interpret
	// them, so neither does policy.
	PassThrough []string
}

// Slot is one positional argument together with what its position means.
type Slot struct {
	Name  string
	Kind  catalog.Kind
	Value string
}

// Name renders the resolved command, such as "sbx policy allow network".
func (inv *Invocation) Name() string { return inv.Command.Name() }

// Has reports whether a flag was given, by its canonical long name.
func (inv *Invocation) Has(name string) bool {
	_, ok := inv.Flags[name]
	return ok
}

// FlagNames lists the flags the argv gave, sorted.
func (inv *Invocation) FlagNames() []string {
	names := make([]string, 0, len(inv.Flags))
	for name := range inv.Flags {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Flag returns the last value given for a flag, which is the one sbx reads for
// every flag that is not repeatable.
func (inv *Invocation) Flag(name string) (string, bool) {
	values, ok := inv.Flags[name]
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[len(values)-1], true
}

// ValuesOfKind returns every positional argument that filled a slot of a kind,
// in the order the argv gave them.
func (inv *Invocation) ValuesOfKind(kind catalog.Kind) []string {
	var values []string
	for _, slot := range inv.Slots {
		if slot.Kind == kind {
			values = append(values, slot.Value)
		}
	}
	return values
}

// Argv resolves a client's arguments, which are the words after "sbx".
func Argv(cat *catalog.Catalog, argv []string) (*Invocation, error) {
	cmd, rest, err := findCommand(cat, argv)
	if err != nil {
		return nil, err
	}
	if cmd.HasSubcommands && len(cmd.Positionals) == 0 {
		// A pure group does nothing on its own; sbx prints help. Resolving it
		// as runnable would let a policy authorize a command that cannot run.
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			return nil, fmt.Errorf("%w: %s has no subcommand %q", ErrUnresolvable, cmd.Name(), rest[0])
		}
	}

	inv := &Invocation{Command: cmd, Flags: map[string][]string{}}
	if err := inv.parse(rest); err != nil {
		return nil, err
	}
	return inv, nil
}

// findCommand walks the leading words of an argv to the deepest command in the
// catalog, allowing the flags that command's ancestors accept.
//
// A flag that appears before the command is complete is only usable if the
// catalog already knows it, because its arity decides whether the next word is
// the flag's value or the subcommand's name. Refusing an unknown flag here is
// what keeps a caller from steering command resolution with a flag this
// catalog has never heard of.
func findCommand(cat *catalog.Catalog, argv []string) (*catalog.Command, []string, error) {
	cmd, ok := cat.Lookup(nil)
	if !ok {
		return nil, nil, fmt.Errorf("%w: the catalog has no root command", ErrUnresolvable)
	}

	// Everything that is not one of the command's own words is handed on for
	// parsing, in the order it was given, so a flag written before the
	// subcommand is still the flag it was.
	path := make([]string, 0, len(argv))
	rest := make([]string, 0, len(argv))

	i := 0
	for ; i < len(argv); i++ {
		token := argv[i]

		if token == "--" {
			break
		}
		if strings.HasPrefix(token, "-") && token != "-" {
			consumed, err := skipFlag(cmd, argv[i:])
			if err != nil {
				return nil, nil, err
			}
			rest = append(rest, argv[i:i+consumed]...)
			i += consumed - 1
			continue
		}

		next, ok := cat.Lookup(append(path[:len(path):len(path)], token))
		if !ok {
			break
		}
		cmd = next
		path = append(path, token)
	}

	return cmd, append(rest, argv[i:]...), nil
}

// skipFlag reports how many tokens a flag occupies while the command is still
// being resolved.
func skipFlag(cmd *catalog.Command, tokens []string) (int, error) {
	token := tokens[0]

	if strings.HasPrefix(token, "--") {
		name, _, attached := strings.Cut(strings.TrimPrefix(token, "--"), "=")
		flag, err := longFlag(cmd, name)
		if err != nil {
			return 0, err
		}
		if attached || !flag.TakesValue {
			return 1, nil
		}
		if len(tokens) < 2 {
			return 0, fmt.Errorf("%w: --%s needs a value", ErrUnresolvable, name)
		}
		return 2, nil
	}

	// A shorthand cluster ends in a value only if its last flag takes one, so
	// parsing it is the only way to know whether the next token belongs to it.
	_, consumedNext, err := parseShorthands(cmd, token, tokens[1:])
	if err != nil {
		return 0, err
	}
	if consumedNext {
		return 2, nil
	}
	return 1, nil
}

func (inv *Invocation) parse(tokens []string) error {
	var positionals []string

parsing:
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]

		if token == "--" {
			rest := tokens[i+1:]
			if inv.Command.PassThrough {
				inv.PassThrough = rest
			} else {
				// Without a pass-through slot, sbx treats everything after "--"
				// as ordinary positional arguments.
				positionals = append(positionals, rest...)
			}
			break
		}

		switch {
		case strings.HasPrefix(token, "--"):
			consumed, err := inv.parseLong(token, tokens[i+1:])
			if err != nil {
				return err
			}
			i += consumed
		case strings.HasPrefix(token, "-") && token != "-":
			values, consumedNext, err := parseShorthands(inv.Command, token, tokens[i+1:])
			if err != nil {
				return err
			}
			for name, value := range values {
				inv.Flags[name] = append(inv.Flags[name], value)
			}
			if consumedNext {
				i++
			}
		default:
			positionals = append(positionals, token)
			if inv.Command.StopFlagsAtFirstPositional {
				// sbx stops reading its own flags here, so everything left
				// belongs to the program it runs. A leading "--" is the
				// separator sbx drops before handing the command over.
				positionals = append(positionals, trimLeadingDashDash(tokens[i+1:])...)
				break parsing
			}
		}
	}

	return inv.fillSlots(positionals)
}

func trimLeadingDashDash(tokens []string) []string {
	if len(tokens) > 0 && tokens[0] == "--" {
		return tokens[1:]
	}
	return tokens
}

// parseLong records one long flag and reports how many further tokens it ate.
func (inv *Invocation) parseLong(token string, rest []string) (int, error) {
	name, attachedValue, attached := strings.Cut(strings.TrimPrefix(token, "--"), "=")
	flag, err := longFlag(inv.Command, name)
	if err != nil {
		return 0, err
	}

	switch {
	case attached:
		inv.Flags[flag.Name] = append(inv.Flags[flag.Name], attachedValue)
		return 0, nil
	case !flag.TakesValue:
		inv.Flags[flag.Name] = append(inv.Flags[flag.Name], "true")
		return 0, nil
	case len(rest) == 0:
		return 0, fmt.Errorf("%w: --%s needs a value", ErrUnresolvable, name)
	default:
		inv.Flags[flag.Name] = append(inv.Flags[flag.Name], rest[0])
		return 1, nil
	}
}

// parseShorthands reads a cluster such as "-it", "-uroot" or "-u=root",
// following the same precedence sbx's flag parser uses, and reports whether the
// cluster's last flag took its value from the following token.
func parseShorthands(cmd *catalog.Command, token string, rest []string) (map[string]string, bool, error) {
	values := map[string]string{}
	shorthands := strings.TrimPrefix(token, "-")

	for len(shorthands) > 0 {
		flag, err := shortFlag(cmd, shorthands[0])
		if err != nil {
			return nil, false, err
		}

		switch {
		case len(shorthands) > 2 && shorthands[1] == '=':
			values[flag.Name] = shorthands[2:]
			return values, false, nil
		case !flag.TakesValue:
			values[flag.Name] = "true"
			shorthands = shorthands[1:]
		case len(shorthands) > 1:
			values[flag.Name] = shorthands[1:]
			return values, false, nil
		case len(rest) > 0:
			values[flag.Name] = rest[0]
			return values, true, nil
		default:
			return nil, false, fmt.Errorf("%w: -%c needs a value", ErrUnresolvable, shorthands[0])
		}
	}
	return values, false, nil
}

func longFlag(cmd *catalog.Command, name string) (catalog.Flag, error) {
	for _, flag := range cmd.Flags {
		if flag.Name == name {
			return flag, nil
		}
	}
	return catalog.Flag{}, fmt.Errorf("%w: %s has no --%s", ErrUnresolvable, cmd.Name(), name)
}

func shortFlag(cmd *catalog.Command, shorthand byte) (catalog.Flag, error) {
	for _, flag := range cmd.Flags {
		if flag.Shorthand == string(shorthand) {
			return flag, nil
		}
	}
	return catalog.Flag{}, fmt.Errorf("%w: %s has no -%c", ErrUnresolvable, cmd.Name(), shorthand)
}

// fillSlots pairs positional arguments with the slots the command declares, so
// a policy can ask which sandbox or which host path an argument named rather
// than guessing from its position.
func (inv *Invocation) fillSlots(positionals []string) error {
	slots := inv.Command.Positionals

	for i, value := range positionals {
		slot, ok := slotAt(slots, i)
		if !ok {
			return fmt.Errorf("%w: %s takes %s, got %d",
				ErrUnresolvable, inv.Command.Name(), describeArity(slots), len(positionals))
		}
		if len(slot.Choices) > 0 && !contains(slot.Choices, value) {
			return fmt.Errorf("%w: %s accepts %s, not %q",
				ErrUnresolvable, inv.Command.Name(), strings.Join(slot.Choices, ", "), value)
		}
		inv.Slots = append(inv.Slots, Slot{Name: slot.Name, Kind: slot.Kind, Value: value})
	}

	for i := len(positionals); i < len(slots); i++ {
		if !slots[i].Optional && !slots[i].Variadic {
			return fmt.Errorf("%w: %s needs %s", ErrUnresolvable, inv.Command.Name(), slots[i].Name)
		}
	}
	return nil
}

// slotAt returns the slot filling position i, which is the trailing variadic
// slot once the fixed slots run out.
func slotAt(slots []catalog.Positional, i int) (catalog.Positional, bool) {
	if i < len(slots) {
		return slots[i], true
	}
	if len(slots) > 0 {
		if last := slots[len(slots)-1]; last.Variadic {
			return last, true
		}
	}
	return catalog.Positional{}, false
}

func describeArity(slots []catalog.Positional) string {
	if len(slots) == 0 {
		return "no arguments"
	}
	names := make([]string, 0, len(slots))
	for _, slot := range slots {
		names = append(names, slot.Name)
	}
	return strings.Join(names, " ")
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
