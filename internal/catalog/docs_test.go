package catalog

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

func docsFS(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	return fsys
}

func buildCatalog(t *testing.T, files map[string]string) *Catalog {
	t.Helper()
	cat, err := FromDocs(docsFS(files), "v1.2.3")
	require.NoError(t, err)
	return cat
}

func command(t *testing.T, cat *Catalog, path ...string) *Command {
	t.Helper()
	cmd, ok := cat.Lookup(path)
	require.True(t, ok, "catalog has no %v", path)
	return cmd
}

func TestFromDocsReadsFlagArity(t *testing.T) {
	cat := buildCatalog(t, map[string]string{"sbx_exec.yaml": `
name: sbx exec
usage: sbx exec [flags] SANDBOX COMMAND [ARG...]
options:
    - name: tty
      shorthand: t
      default_value: "false"
    - name: user
      shorthand: u
    - name: env
      shorthand: e
      default_value: '[]'
    - name: cpus
      default_value: "0"
inherited_options:
    - name: debug
      shorthand: D
      default_value: "false"
`})

	flags := map[string]Flag{}
	for _, flag := range command(t, cat, "exec").Flags {
		flags[flag.Name] = flag
	}

	// A boolean is the only kind that does not consume the next argument.
	require.False(t, flags["tty"].TakesValue)
	require.False(t, flags["debug"].TakesValue, "an inherited flag is accepted here too")
	require.True(t, flags["user"].TakesValue, "an omitted default means a string flag")
	require.True(t, flags["env"].TakesValue)
	require.True(t, flags["env"].Repeatable)
	require.True(t, flags["cpus"].TakesValue, "a numeric default still consumes a value")
	require.Equal(t, "t", flags["tty"].Shorthand)
}

func TestFromDocsReadsPositionalSlots(t *testing.T) {
	cat := buildCatalog(t, map[string]string{"sbx_exec.yaml": `
name: sbx exec
usage: sbx exec [flags] SANDBOX COMMAND [ARG...]
`})

	require.Equal(t, []Positional{
		{Name: "SANDBOX", Kind: KindSandbox},
		{Name: "COMMAND", Kind: KindCommand},
		{Name: "ARG", Kind: KindCommand, Optional: true, Variadic: true},
	}, command(t, cat, "exec").Positionals)
}

func TestFromDocsIgnoresFlagHintsInUsage(t *testing.T) {
	// A usage line repeats some flags for readability. Reading them as
	// positional slots would shift every real slot's index.
	cat := buildCatalog(t, map[string]string{
		"sbx_policy_allow_network.yaml": `
name: sbx policy allow network
usage: sbx policy allow network [--sandbox SANDBOX] RESOURCES [flags]
`,
		"sbx_mcp_add.yaml": `
name: sbx mcp add
usage: sbx mcp add <name> (--url <url> | --command <cmd>) [flags]
`,
	})

	require.Equal(t, []Positional{{Name: "RESOURCES", Kind: KindNetwork}},
		command(t, cat, "policy", "allow", "network").Positionals)
	require.Equal(t, []Positional{{Name: "NAME", Kind: KindOther}},
		command(t, cat, "mcp", "add").Positionals)
}

func TestFromDocsMarksPassThroughArguments(t *testing.T) {
	cat := buildCatalog(t, map[string]string{"sbx_run.yaml": `
name: sbx run
usage: sbx run [flags] [AGENT] [PATH...] [-- AGENT_ARGS...]
`})

	cmd := command(t, cat, "run")
	require.True(t, cmd.PassThrough)
	require.Equal(t, []Positional{
		{Name: "AGENT", Kind: KindOther, Optional: true},
		{Name: "PATH", Kind: KindPath, Optional: true, Variadic: true},
	}, cmd.Positionals)
}

func TestFromDocsDropsTheSubcommandPlaceholder(t *testing.T) {
	// "sbx policy COMMAND" names a subcommand, while the COMMAND of "sbx exec"
	// is a real argument.
	cat := buildCatalog(t, map[string]string{
		"sbx_policy.yaml": `
name: sbx policy
usage: sbx policy COMMAND
`,
		"sbx_policy_ls.yaml": `
name: sbx policy ls
usage: sbx policy ls [SANDBOX] [flags]
`,
		"sbx_exec.yaml": `
name: sbx exec
usage: sbx exec [flags] SANDBOX COMMAND
`,
	})

	policy := command(t, cat, "policy")
	require.True(t, policy.HasSubcommands)
	require.Empty(t, policy.Positionals)

	exec := command(t, cat, "exec")
	require.False(t, exec.HasSubcommands)
	require.Len(t, exec.Positionals, 2)
}

func TestFromDocsKeepsPositionalsOnACommandThatAlsoHasSubcommands(t *testing.T) {
	cat := buildCatalog(t, map[string]string{
		"sbx_create.yaml": `
name: sbx create
usage: sbx create [flags] AGENT PATH [PATH...]
`,
		"sbx_create_claude.yaml": `
name: sbx create claude
usage: sbx create claude PATH [PATH...] [flags]
`,
	})

	create := command(t, cat, "create")
	require.True(t, create.HasSubcommands)
	require.Len(t, create.Positionals, 3, "sbx create runs on its own as well as grouping")
}

func TestFromDocsReadsLiteralChoices(t *testing.T) {
	cat := buildCatalog(t, map[string]string{
		"sbx_policy_init.yaml": `
name: sbx policy init
usage: sbx policy init <allow-all|balanced|deny-all> [flags]
`,
		"sbx_template_rm.yaml": `
name: sbx template rm
usage: sbx template rm TAG|ID [flags]
`,
	})

	require.Equal(t, []Positional{{Name: "CHOICE", Kind: KindOther, Choices: []string{"allow-all", "balanced", "deny-all"}}},
		command(t, cat, "policy", "init").Positionals)

	// Upper case alternatives name two kinds of value, not two values.
	require.Equal(t, []Positional{{Name: "TAG|ID", Kind: KindReference}},
		command(t, cat, "template", "rm").Positionals)
}

func TestFromDocsScopesAmbiguousSlotNamesToTheirCommand(t *testing.T) {
	cat := buildCatalog(t, map[string]string{
		"sbx_policy_check_network.yaml": `
name: sbx policy check network
usage: sbx policy check network TARGET [flags]
`,
		"sbx_daemon_log-level_set.yaml": `
name: sbx daemon log-level set
usage: sbx daemon log-level set <target> <level> [flags]
`,
	})

	require.Equal(t, KindNetwork, command(t, cat, "policy", "check", "network").Positionals[0].Kind)
	require.Equal(t, KindOther, command(t, cat, "daemon", "log-level", "set").Positionals[0].Kind,
		"a daemon component is not a network endpoint")
}

func TestFromDocsRecordsTheVersionItDescribes(t *testing.T) {
	cat := buildCatalog(t, map[string]string{"sbx.yaml": "name: sbx\nusage: sbx\n"})
	require.Equal(t, "v1.2.3", cat.SbxVersion)
}

func TestFromDocsRejectsAnEmptyTree(t *testing.T) {
	_, err := FromDocs(docsFS(nil), "")
	require.ErrorContains(t, err, "no CLI reference files found")
}

func TestLongestPrefixStopsAtTheDeepestCommand(t *testing.T) {
	cat := buildCatalog(t, map[string]string{
		"sbx.yaml":                  "name: sbx\nusage: sbx\n",
		"sbx_policy.yaml":           "name: sbx policy\nusage: sbx policy COMMAND\n",
		"sbx_policy_allow.yaml":     "name: sbx policy allow\nusage: sbx policy allow COMMAND\n",
		"sbx_policy_allow_net.yaml": "name: sbx policy allow network\nusage: sbx policy allow network RESOURCES [flags]\n",
	})

	cmd, used := cat.LongestPrefix([]string{"policy", "allow", "network", "localhost:7391"})
	require.Equal(t, "sbx policy allow network", cmd.Name())
	require.Equal(t, 3, used)

	cmd, used = cat.LongestPrefix([]string{"policy", "allow"})
	require.Equal(t, "sbx policy allow", cmd.Name())
	require.Equal(t, 2, used)

	cmd, used = cat.LongestPrefix([]string{"nonesuch"})
	require.Equal(t, "sbx", cmd.Name())
	require.Zero(t, used)
}

func TestEmbeddedCatalogDescribesTheRealCLI(t *testing.T) {
	cat, err := Embedded()
	require.NoError(t, err)

	// A handful of invariants the resolver depends on, checked against the
	// committed catalog so a regeneration cannot quietly break them.
	exec := command(t, cat, "exec")
	require.Equal(t, KindSandbox, exec.Positionals[0].Kind)
	for _, flag := range exec.Flags {
		if flag.Name == "workdir" {
			require.True(t, flag.TakesValue)
		}
	}

	create := command(t, cat, "create")
	require.True(t, create.HasSubcommands)
	require.NotEmpty(t, create.Positionals)

	require.True(t, command(t, cat, "run").PassThrough)
	require.NotEmpty(t, cat.SbxVersion, "the catalog records which sbx it describes")
}
