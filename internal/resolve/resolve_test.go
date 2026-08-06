package resolve

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cdupuis/sbx-dev/internal/catalog"
)

// Resolution is tested against the committed catalog rather than a fixture,
// because its value is that it agrees with the real CLI.
func realCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Embedded()
	require.NoError(t, err)
	return cat
}

func resolve(t *testing.T, argv ...string) *Invocation {
	t.Helper()
	inv, err := Argv(realCatalog(t), argv)
	require.NoError(t, err)
	return inv
}

func refuse(t *testing.T, argv ...string) error {
	t.Helper()
	_, err := Argv(realCatalog(t), argv)
	require.ErrorIs(t, err, ErrUnresolvable)
	return err
}

func slotValues(inv *Invocation) []string {
	values := make([]string, 0, len(inv.Slots))
	for _, slot := range inv.Slots {
		values = append(values, slot.Name+"="+slot.Value)
	}
	return values
}

func TestArgvFindsTheDeepestCommand(t *testing.T) {
	inv := resolve(t, "policy", "allow", "network", "localhost:7391")

	require.Equal(t, "sbx policy allow network", inv.Name())
	require.Equal(t, []string{"RESOURCES=localhost:7391"}, slotValues(inv))
	require.Equal(t, []string{"localhost:7391"}, inv.ValuesOfKind(catalog.KindNetwork))
}

func TestArgvSeparatesAFlagValueFromAPositional(t *testing.T) {
	// The whole point: "--sandbox other" is one flag and its value, not two
	// positional arguments, and only the catalog's arity says so.
	inv := resolve(t, "policy", "allow", "network", "--sandbox", "other", "localhost:7391")

	sandbox, ok := inv.Flag("sandbox")
	require.True(t, ok)
	require.Equal(t, "other", sandbox)
	require.Equal(t, []string{"RESOURCES=localhost:7391"}, slotValues(inv))
}

func TestArgvReadsAttachedAndSeparatedFlagValuesAlike(t *testing.T) {
	attached := resolve(t, "exec", "--workdir=/srv", "box", "ls")
	separated := resolve(t, "exec", "--workdir", "/srv", "box", "ls")

	for _, inv := range []*Invocation{attached, separated} {
		workdir, ok := inv.Flag("workdir")
		require.True(t, ok)
		require.Equal(t, "/srv", workdir)
		require.Equal(t, []string{"SANDBOX=box", "COMMAND=ls"}, slotValues(inv))
	}
}

func TestArgvReadsShorthandClusters(t *testing.T) {
	inv := resolve(t, "exec", "-it", "box", "bash")

	require.True(t, inv.Has("interactive"))
	require.True(t, inv.Has("tty"))
	require.Equal(t, []string{"SANDBOX=box", "COMMAND=bash"}, slotValues(inv))
}

func TestArgvReadsAShorthandValueInEveryForm(t *testing.T) {
	for _, argv := range [][]string{
		{"exec", "-u", "root", "box", "ls"},
		{"exec", "-uroot", "box", "ls"},
		{"exec", "-u=root", "box", "ls"},
		{"exec", "-itu", "root", "box", "ls"},
	} {
		inv := resolve(t, argv...)
		user, ok := inv.Flag("user")
		require.True(t, ok, "%v", argv)
		require.Equal(t, "root", user, "%v", argv)
		require.Equal(t, []string{"SANDBOX=box", "COMMAND=ls"}, slotValues(inv), "%v", argv)
	}
}

func TestArgvCollectsRepeatedFlags(t *testing.T) {
	inv := resolve(t, "exec", "-e", "A=1", "--env", "B=2", "box", "ls")

	require.Equal(t, []string{"A=1", "B=2"}, inv.Flags["env"])
}

func TestArgvAcceptsPersistentFlagsBeforeTheSubcommand(t *testing.T) {
	inv := resolve(t, "-D", "ls")

	require.Equal(t, "sbx ls", inv.Name())
	require.True(t, inv.Has("debug"))
}

func TestArgvRefusesAFlagWhoseArityItCannotKnow(t *testing.T) {
	// An unknown flag before the subcommand could consume the next word, which
	// would change which command runs. Hidden flags land here too, which is why
	// a flag missing from the catalog is refused rather than assumed harmless.
	err := refuse(t, "--app-name", "ls", "rm", "box")
	require.ErrorContains(t, err, "has no --app-name")

	require.ErrorContains(t, refuse(t, "exec", "--nonesuch", "box", "ls"), "has no --nonesuch")
	require.ErrorContains(t, refuse(t, "exec", "-Z", "box", "ls"), "has no -Z")
}

func TestArgvRefusesAFlagFromAnotherCommand(t *testing.T) {
	// --privileged belongs to exec, not ls, and sbx would reject it too.
	require.ErrorContains(t, refuse(t, "ls", "--privileged"), "sbx ls has no --privileged")
}

func TestArgvRefusesAValueLessFlagAtTheEnd(t *testing.T) {
	require.ErrorContains(t, refuse(t, "exec", "--workdir"), "needs a value")
	require.ErrorContains(t, refuse(t, "exec", "-u"), "needs a value")
	require.ErrorContains(t, refuse(t, "create", "claude", "/work", "--name"), "needs a value")
}

func TestArgvGivesTheInnerCommandItsOwnFlags(t *testing.T) {
	// sbx exec stops reading its own flags at the sandbox name, so "-la" is an
	// argument to ls. Reading it as an sbx flag would resolve a command line
	// that never runs, and refuse invocations sbx accepts.
	inv := resolve(t, "exec", "-it", "box", "ls", "-la", "--color=never")

	require.True(t, inv.Has("tty"))
	require.False(t, inv.Has("color"))
	require.Equal(t, []string{"SANDBOX=box", "COMMAND=ls", "ARG=-la", "ARG=--color=never"}, slotValues(inv))
}

func TestArgvDropsTheSeparatorSbxStripsBeforeTheInnerCommand(t *testing.T) {
	inv := resolve(t, "exec", "box", "--", "ls", "-la")

	require.Equal(t, []string{"SANDBOX=box", "COMMAND=ls", "ARG=-la"}, slotValues(inv))
}

func TestArgvFillsAVariadicSlotWithEveryRemainingArgument(t *testing.T) {
	inv := resolve(t, "exec", "box", "sh", "-lc", "echo hi")

	// Everything after COMMAND belongs to the command being run, so the
	// arguments are not read as sbx's own flags.
	require.Equal(t, []string{"SANDBOX=box", "COMMAND=sh", "ARG=-lc", "ARG=echo hi"}, slotValues(inv))
}

func TestArgvRefusesTooManyPositionals(t *testing.T) {
	require.ErrorContains(t, refuse(t, "ports", "one", "two"), "sbx ports takes SANDBOX")
}

func TestArgvRefusesAMissingRequiredPositional(t *testing.T) {
	require.ErrorContains(t, refuse(t, "ports"), "sbx ports needs SANDBOX")
	require.ErrorContains(t, refuse(t, "kit", "add", "box"), "needs REFERENCE")
}

func TestArgvAcceptsAnAbsentOptionalPositional(t *testing.T) {
	inv := resolve(t, "policy", "ls")

	require.Equal(t, "sbx policy ls", inv.Name())
	require.Empty(t, inv.Slots)
}

func TestArgvChecksLiteralChoices(t *testing.T) {
	inv := resolve(t, "policy", "init", "balanced")
	require.Equal(t, []string{"CHOICE=balanced"}, slotValues(inv))

	require.ErrorContains(t, refuse(t, "policy", "init", "allow-everything"), "accepts allow-all, balanced, deny-all")
}

func TestArgvKeepsPassThroughArgumentsOpaque(t *testing.T) {
	inv := resolve(t, "run", "claude", "/work", "--", "--dangerously-skip-permissions")

	require.Equal(t, "sbx run", inv.Name())
	require.Equal(t, []string{"AGENT=claude", "PATH=/work"}, slotValues(inv))
	require.Equal(t, []string{"--dangerously-skip-permissions"}, inv.PassThrough)
	require.False(t, inv.Has("dangerously-skip-permissions"), "a forwarded argument is not one of sbx's flags")
}

func TestArgvTreatsArgumentsAfterADashDashAsPositionalWhenNothingForwardsThem(t *testing.T) {
	inv := resolve(t, "stop", "--", "box")

	require.Empty(t, inv.PassThrough)
	require.Equal(t, []string{"SANDBOX=box"}, slotValues(inv))
}

func TestArgvRefusesAnUnknownSubcommandOfAGroup(t *testing.T) {
	require.ErrorContains(t, refuse(t, "policy", "nonesuch"), "sbx policy has no subcommand")
}

func TestArgvResolvesACommandThatIsAlsoAGroup(t *testing.T) {
	group := resolve(t, "create", "claude", "/work")
	require.Equal(t, "sbx create claude", group.Name())
	require.Equal(t, []string{"PATH=/work"}, slotValues(group))

	own := resolve(t, "create", "nonesuch-agent", "/work")
	require.Equal(t, "sbx create", own.Name(), "an unknown agent falls through to sbx create's own AGENT slot")
	require.Equal(t, []string{"AGENT=nonesuch-agent", "PATH=/work"}, slotValues(own))
}

func TestArgvNamesTheTargetSandbox(t *testing.T) {
	for _, tc := range []struct {
		argv    []string
		sandbox string
	}{
		{[]string{"exec", "box", "ls"}, "box"},
		{[]string{"ports", "box"}, "box"},
		{[]string{"kit", "add", "box", "example/kit:1"}, "box"},
		{[]string{"stop", "box"}, "box"},
	} {
		inv := resolve(t, tc.argv...)
		require.Equal(t, []string{tc.sandbox}, inv.ValuesOfKind(catalog.KindSandbox), "%v", tc.argv)
	}
}

func TestArgvNamesHostPaths(t *testing.T) {
	inv := resolve(t, "create", "claude", "/work", "/opt/src")
	require.Equal(t, []string{"/work", "/opt/src"}, inv.ValuesOfKind(catalog.KindPath))

	cp := resolve(t, "cp", "/etc/hosts", "box:/tmp/hosts")
	require.Equal(t, []string{"/etc/hosts", "box:/tmp/hosts"}, cp.ValuesOfKind(catalog.KindPath))
}

func TestArgvReportsFlagNamesSorted(t *testing.T) {
	inv := resolve(t, "exec", "-it", "-u", "root", "box", "ls")
	require.Equal(t, []string{"interactive", "tty", "user"}, inv.FlagNames())
}

func TestArgvResolvesTheBareRootCommand(t *testing.T) {
	inv := resolve(t)
	require.Equal(t, "sbx", inv.Name())
}
