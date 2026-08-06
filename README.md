# sbx-warden

Lets an agent inside a sandbox drive Docker Sandboxes on the host through the
host's own [`sbx`](https://github.com/docker/sandboxes) CLI, and decides per
sandbox what it may ask for.

> [!WARNING]
> **This dismantles the boundary a sandbox exists to enforce.** A sandbox
> confines an agent; running this hands that agent your host's control plane,
> which is enough to escape. Both escapes below were reproduced against a
> default-deny policy, from a sandbox whose only workspace was an empty
> directory:
>
> - **Read and write any file on the host.** `sbx create shell /any/host/path`
>   mounts a host directory into a new sandbox, and `sbx exec` reads and writes
>   it as your user. The agent needs no access to the path itself.
> - **Lift its own network restrictions.** Running `sbx policy allow network
>   example.com:443` from inside made that domain reachable where it had just
>   been blocked, and the rule landed at *global* scope, so it applied to every
>   other sandbox on the host too.
>
> Both are refused by the [policy](#policy) a server enforces by default, which
> grants little more than reading. They are what a sandbox reaches as soon as that
> policy is widened or switched off, so treat widening it as the decision it is.
>
> A coding agent acts on what it reads — a repository, an issue, a web page — so
> assume anything it reads can reach your host. Run this only where that is
> acceptable. See [Security](#security).

Two binaries:

| Binary       | Runs on          | Role                                                                    |
| ------------ | ---------------- | ----------------------------------------------------------------------- |
| `sbx-warden` | the host         | Identifies the caller, authorizes the command, runs the real `sbx`.     |
| `sbx`        | inside a sandbox | Forwards its arguments to `sbx-warden` and relays stdio.                |

Every argument is passed through untouched, so all `sbx` commands, flags and
help text work as if the CLI were installed locally. Interactive commands work
too: the client negotiates a remote PTY when its stdin is a terminal, and
forwards window-size changes.

## Install

The two binaries install by different routes, because they live in different
places. You install the server on your host. The client belongs inside a sandbox
that does not exist yet, so the kit installs it as each sandbox is created.

### The server, on your host

On Linux or macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/cdupuis/sbx-warden/main/install.sh | sh -s -- --server
```

On Windows, in PowerShell:

```powershell
$env:SBX_WARDEN_COMPONENTS = 'server'
irm https://raw.githubusercontent.com/cdupuis/sbx-warden/main/install.ps1 | iex
```

Then [run it](#run-the-server-on-the-host). Dropping `--server` installs both
binaries, which is only worth doing if you want a client on the host too, for
testing against the server directly.

### The client, in a sandbox

Use the kit. It installs the client while a sandbox is being created, allows the
egress it needs, and points it at the host, so there is nothing to install inside
the sandbox afterwards, and nothing to clone to get it.

Grant the sandbox first, then create it under that name:

```bash
sbx-warden grant my-sandbox
sbx create shell . --name my-sandbox \
  --kit 'git+https://github.com/cdupuis/sbx-warden.git#ref=v0.5.0&dir=kit/sbx-warden'
```

Granting is what lets the server recognise the sandbox, and it is the only way
in: there is no shared secret to copy. The name is not decoration — the token is
signed over it, so the grant and the `--name` have to agree. Grant before you
create, because a sandbox picks its token up at creation.

Keep the kit reference quoted, or the shell reads the `&` before `dir=` as a
request to run the command in the background.

Remote kits are gated by an allowlist that ships allowing Docker's own sources,
so the first attempt is refused until `github.com/cdupuis/` joins it. The refusal
prints the exact `sbx settings set kit.allowedSources` command to run, with your
existing entries preserved — use that rather than copying a list from here, which
would replace whatever you already allow.

Prefer this over running the installer inside a sandbox. Sandboxes are
disposable, so installing by hand is work repeated for every one you create, and
it happens from inside, where reaching GitHub needs egress you have to grant
first and you get whichever release is latest at that moment. The kit declares
the egress alongside the install and pins the release, so every sandbox made from
it gets the same client.

[Set up the client in a sandbox](#set-up-the-client-in-a-sandbox) covers what the
kit configures, how to add it to a sandbox that already exists, and the by-hand
route.

### Installer reference

Both installers download the latest GitHub release, verify it against the
published `checksums.txt`, and install into `/usr/local/bin` when it is writable
or `~/.local/bin` otherwise (`%LOCALAPPDATA%\sbx-warden\bin` on Windows). They never
invoke `sudo`, since a piped script has no terminal to prompt on.

Because the client is called `sbx`, installing it where a real Docker Sandboxes
CLI already lives would shadow that CLI. The installers detect this and skip the
client rather than break your `sbx`; use `--force` or `--dir` if you meant it.

| Option                  | Environment variable    | Purpose                          |
| ----------------------- | ----------------------- | -------------------------------- |
| `--client` / `--server` | `SBX_WARDEN_COMPONENTS`    | Which binaries to install.       |
| `--version VERSION`     | `SBX_WARDEN_VERSION`       | Install a specific release.      |
| `--dir DIRECTORY`       | `SBX_WARDEN_INSTALL_DIR`   | Where to install.                |
| `--force`               | —                       | Replace a foreign `sbx`.         |
| —                       | `SBX_WARDEN_DOWNLOAD_BASE` | Mirror serving release archives. |

Piping to `iex` cannot pass parameters, so the Windows installer reads the
environment variables above.

## Build from source

```bash
task build                 # ./bin/sbx-warden and ./bin/sbx for this host
task build:client:all      # linux/amd64 and linux/arm64 clients for sandboxes
```

## Run the server on the host

```bash
sbx-warden --addr 127.0.0.1:7391
```

On first start it generates the key that signs identity tokens at
`~/.sbx-warden/identity.key` and prints how to let a sandbox in. `sbx-warden grant`
reads the same file, so the two work in either order.

It also fetches its [default policy](#the-default) from GitHub, and will not start
without it. Point `--policy-map` at a local file to work offline.

The server refuses to bind anything but loopback unless you pass
`--allow-any-bind`. Loopback is both sufficient and safest: when a sandbox
connects to `host.docker.internal`, the egress proxy rewrites that to
`localhost` and `sandboxd` — which runs on the host — performs the dial, so the
connection arrives on the host's own loopback. Binding a routable address would
publish your `sbx` CLI to the LAN and buys nothing.

## Set up the client in a sandbox

### With the kit

The [install section](#the-client-in-a-sandbox) has the command. The kit is a v2
mixin, so it composes with any agent rather than replacing one: it installs the
pinned client release into `/usr/local/bin`, exports `SBX_WARDEN_ADDR`, and allows
the egress those need. It carries no credential, and cannot: kit environment
values are literal, so a token in the kit would be a secret committed to a
repository, and a token names one sandbox while a kit is used by many.

`sbx-warden grant` supplies the credential instead. It registers the token as a
sandbox-scoped secret, which sets `SBX_WARDEN_TOKEN` inside the sandbox to a
placeholder that the egress proxy substitutes, so the token reaches the server
without ever being readable in the sandbox.

The kit allows exactly one host port, `localhost:7391`, so the sandbox can reach
the server and nothing else on your host — not even another port on the same
host. Read that as tidiness rather than containment: the one port it does reach
is the host's `sbx` CLI, and the network policy the kit installs is itself
something the sandbox could rewrite through that port. What actually constrains
this is the server's [policy](#policy) and `--allow-command`, not the allow list.

Running the server elsewhere means changing both `SBX_WARDEN_ADDR` and the
`permissions.network.allow` entry in the kit, because a rule naming one port
does not match another.

Because the kit pins the client release it installs, its `version` tracks the
client version rather than moving independently.

The `#ref=` in the reference pins the kit the same way, so a sandbox created from
it months from now still gets this kit installing this client. Point it at
`#ref=main` to follow the branch instead, or at a commit SHA for a reference that
cannot move at all — a tag can be repointed, a SHA cannot. A checkout of this
repository can also name the kit by path, as `./kit/sbx-warden`, which is what
`task kit:validate` does while you are changing the kit itself.

### Adding it to a sandbox that already exists

A sandbox that predates the kit does not need the by-hand route: `sbx kit add`
recreates it with the kit applied, keeping kit-owned volumes and workspace data.
Recreating is also when a sandbox picks up its token, so grant it in the same
pass:

```bash
sbx-warden grant my-sandbox
sbx kit add my-sandbox 'git+https://github.com/cdupuis/sbx-warden.git#ref=v0.5.0&dir=kit/sbx-warden'
```

Granting on its own has no effect until the sandbox is recreated, because a
container's environment is fixed at creation. Rotating a token later is the
exception: regranting reuses the same placeholder, so the substituted value
changes without recreating anything.

### By hand

Two cases are left for this: trying a locally built client before you release it,
and sandboxes old enough that `sbx kit add` refuses them, which it does for any
sandbox created before that command shipped.

Allow the port in the sandbox network policy. The rule must name `localhost`,
not `host.docker.internal`, because the proxy rewrites the request host before
evaluating policy while rules are matched verbatim:

```bash
sbx policy allow network localhost:7391
```

Get the client into the sandbox. Either run the installer inside it, which needs
`raw.githubusercontent.com`, `github.com` and
`release-assets.githubusercontent.com` allowed in the sandbox's policy:

```bash
curl -fsSL https://raw.githubusercontent.com/cdupuis/sbx-warden/main/install.sh | sh -s -- --client
```

That lands in `~/.local/bin`, which is writable and already first on `PATH` in
the standard sandbox images, so pass no `--dir`: `/usr/local/bin` is root-owned
and the agent cannot write to it.

Or copy a locally built binary in, which needs no extra egress:

```bash
task install:client SANDBOX=my-sandbox     # or: sbx cp ./bin/sbx-linux-arm64 my-sandbox:/usr/local/bin/sbx
```

Point the client at the host, and give the sandbox a token. `--print-token`
prints one instead of registering it as a secret, which is the by-hand
equivalent:

```bash
sbx-warden grant --print-token my-sandbox      # on the host
```

Then, inside the sandbox:

```bash
export SBX_WARDEN_ADDR=host.docker.internal:7391
export SBX_WARDEN_TOKEN=<token printed by sbx-warden grant>
sbx ls
```

A sandbox that holds its own token can read it, which the secret route avoids.
It is still no more powerful than the sandbox it names, because the name is
signed: it cannot be edited into another sandbox's token.

## Configuration

The client takes no flags of its own, so that every flag reaches the real CLI.
It reads:

| Variable                | Default                     | Purpose                                       |
| ----------------------- | --------------------------- | --------------------------------------------- |
| `SBX_WARDEN_ADDR`          | `host.docker.internal:7391` | Server address.                               |
| `SBX_WARDEN_TOKEN`         | —                           | Identity token, set by `sbx-warden grant`.       |
| `SBX_WARDEN_FORWARD_ENV`   | —                           | Comma-separated env var names to send along.  |
| `SBX_WARDEN_NO_TTY`        | —                           | Set to any value to suppress PTY allocation.  |
| `SBX_WARDEN_PRINT_VERSION` | —                           | Print the client's version and exit.          |

`SBX_WARDEN_TOKEN` is required and usually holds a placeholder rather than the token
itself; see [Policy](#policy).

Environment variables are not forwarded by default; name them explicitly in
`SBX_WARDEN_FORWARD_ENV` when a command needs them. The child process otherwise
inherits the server's environment.

Server flags: `--addr`, `--sbx`, `--workdir`, `--allow-command`, `--allow-env`,
`--allow-any-bind`, `--verbose`, `--version`, `--policy-map` and `--key-file`.
Run `sbx-warden --help` for details.

The client reports its own version through `SBX_WARDEN_PRINT_VERSION` rather than a
flag, because every argument belongs to the remote CLI.

## Security

Access is granted one sandbox at a time. There is no shared secret: every session
authenticates with a token naming a single sandbox, so nothing you hand out is
usable by anything you did not name, and `sbx-warden grant` is the only way in.

The signing key is what that rests on. Whoever holds `~/.sbx-warden/identity.key`
can mint a token for any name, so treat it like an SSH key; it is written `0600`
in a `0700` directory. Loopback binding limits *who* can present a token, not
what a token permits.

Two controls narrow what a granted sandbox may then do, and they answer different
questions.

`--allow-command` restricts every session to named subcommands, whoever is
calling:

```bash
sbx-warden --allow-command ls,ps,logs
```

Choose that list as if the caller were hostile. It narrows the blast radius
rather than removing it: `ls` still discloses every sandbox name and host
workspace path, and `logs` still discloses whatever the agents there have
printed. The escapes above need `create`, `exec` and `policy`, so a list that
omits all three is the difference between reconnaissance and host access.

[Policy](#policy) is the sharper instrument, because it can tell callers apart:
it decides per sandbox what that sandbox may do. It is on by default, so the
escapes above are refused until you widen it.

## Policy

Identity answers *which sandbox is this*. Policy answers *may that sandbox run
this command*, and the server asks them in that order.

Every sandbox needs a grant regardless:

```bash
sbx-warden grant orchestrator
sbx-warden grant worker-1
```

Each token is an HMAC over the sandbox's name, so it cannot be forged or
transplanted between sandboxes, and by default the sandbox never holds it:
`grant` registers it as a sandbox-scoped secret and the egress proxy substitutes
the real value into the sandbox's handshake. Granting again rotates the token,
retiring the previous one without recreating the sandbox.

### The default

A server started with no `--policy-map` authorizes against the map in
[`policies/`](policies), read from the `main` branch of the repository it was
built from:

```
https://raw.githubusercontent.com/cdupuis/sbx-warden/main/policies/policy-map.yaml
```

The repository comes from the Go module path, so a fork defaults to the policies
it ships rather than to these. What that default grants is read-only access,
plus [the guardrails](#the-shipped-policies) that no role file can restore, so a
server is useful on first start without being open.

Three consequences worth knowing:

- **Startup reads it over the network**, and fails rather than starting with
  fewer rules than intended. Pass a path to avoid the fetch.
- **It tracks `main`**, so whoever can push there decides what every sandbox may
  do. Pin a tag or vendor the files locally where that matters.
- **Policy can be switched off** with an empty value, which is the only way back
  to an unrestricted server:

```bash
sbx-warden --policy-map=""                        # no policy at all
sbx-warden --policy-map policies/policy-map.yaml  # a local copy, no fetch
```

### The two layers

A **policy map** says which policies apply to whom. A **policy file** says what
those policies allow. Keeping them apart means a role is written once and handed
to any number of sandboxes.

```yaml
# policies/policy-map.yaml
bindings:
  - sandboxes: "*"
    policies: [baseline.cedar, readonly.cedar]

  - sandboxes: "worker-*"
    policies: worker.cedar
    groups: workers

  - sandboxes: orchestrator
    policies: orchestrator.cedar
    groups: orchestrators
```

Patterns are globs over the sandbox name: `*` matches any run of characters, `?`
a single one, and a pattern without a wildcard is an exact name. Policies resolve
against the map, so the directory can be moved or checked out anywhere.
`groups` is optional and lets a policy say `principal in SBX::Group::"workers"`
rather than naming each sandbox.

### Serving the map over http

The default is fetched this way, and so is any map you point at yourself, which is
how several hosts enforce one set of rules instead of each keeping a copy that
drifts:

```bash
sbx-warden --policy-map https://config.example.com/sbx/policy-map.yaml
```

Resolution works the same way, one level up: a policy named `worker.cedar` in
that map is fetched from `https://config.example.com/sbx/worker.cedar`. The same
map therefore works from a directory or from a server without editing it. A
binding may also name a full URL, so a local map can pull in a shared policy.

What a remote map cannot do is name anything on the host reading it. References
resolve as URLs, so `/etc/shadow` in a served map is a path on the server that
served it, and any other scheme — `file://` in particular — is refused outright.

Policies are fetched once, while the server starts, over a verified TLS
connection when the URL is `https`. A map or policy that cannot be read fails
startup rather than starting with fewer rules than intended, and changes to a
served policy take effect on restart.

Serving them over plaintext `http://` is allowed and warned about, because
whoever can answer or intercept those requests decides what every sandbox may do:

```
WARN reading policy over plaintext http: http://config/policy-map.yaml
```

Every binding that matches applies, so **order does not matter** and a baseline
bound to `*` cannot be skipped by an entry below it. Cedar decides the rest:
permits accumulate, and a forbid in any matching file beats all of them. That is
what makes `baseline.cedar` a guardrail rather than a default — no role file can
restore what it forbids.

A sandbox that matches no binding is granted nothing, and is told exactly that,
so a missing binding does not read as a rule that refused. A policy that should
reach every sandbox is bound to `*`; there is no separate way to say "everyone".

### The shipped policies

`policies/` holds four files meant to be composed, not used alone:

| File                 | Grants                                                                     |
| -------------------- | -------------------------------------------------------------------------- |
| `baseline.cedar`     | Nothing. Forbids the credential store, the daemon, publishing, and `--privileged`. |
| `readonly.cedar`     | Commands that only report state.                                           |
| `worker.cedar`       | Running commands in *itself* and copying files under the working directory. |
| `orchestrator.cedar` | Creating, destroying, changing and running in sandboxes, confined to the working directory. |

Two conditions carry most of the confinement. `context.targetsSelf` holds only
when every sandbox a command names is the caller, so a worker cannot reach a
sibling — not even by naming itself alongside one. `context.hostPathsUnderWorkdir`
holds only when every host path lies under the directory `sbx-warden` runs in, which
is what keeps `sbx create` from mounting, and `sbx cp` from reading, the rest of
the filesystem. Both are computed from the parse the server already performed, so
neither can be talked around with `..` or a relative path.

### Writing rules

Policies are [Cedar](https://www.cedarpolicy.com). A request is the calling
sandbox as principal, the command as action, the sandbox it acts on (or the host)
as resource, and the parsed command line as context.

Actions belong to **capability groups** — `read`, `createSandbox`,
`destroySandbox`, `changeSandbox`, `runInSandbox`, `touchHostFiles`,
`writePolicy`, `writeSecrets`, `inspectSecrets`, `controlDaemon`,
`publishArtifacts` — so a rule grants a capability rather than a list of command
names and keeps meaning what it meant as sbx grows. A command in no group can
only be granted by name, which is why a new sbx command is never swept in by
accident.

```cedar
// A capability, granted to a group.
permit (
    principal in SBX::Group::"workers",
    action in SBX::Action::"runInSandbox",
    resource
) when { context.targetsSelf };

// A pattern, without a group.
permit (
    principal,
    action in SBX::Action::"read",
    resource
) when { principal.name like "probe-*" };

// One command by name, held for confirmation rather than simply taken.
@requireApproval("a new network rule changes what a sandbox can reach")
permit (
    principal in SBX::Group::"orchestrators",
    action == SBX::Action::"policy allow network",
    resource
);
```

An approved-but-unconfirmed request is reported as needing approval and is not
run, so `@requireApproval` withholds a permit rather than granting it quietly.

### The vocabulary

`policies/sbx.cedarschema` is the schema: every entity type, every action sbx
offers with the groups it belongs to, and every context attribute with its type.
It is generated from the embedded command catalog, so it cannot claim an action
sbx does not have or omit one it does. Regenerate it with `task policy:schema`
after regenerating the catalog.

The schema is checked, not decorative. Tests parse it, confirm it matches the
catalog, confirm it describes exactly the attributes a real request carries, and
type-check every shipped policy against it in strict mode — so a rule naming an
attribute or action that does not exist fails the build instead of silently never
matching.

The one gap is `context.flagValues`, which holds each flag's value keyed by flag
name. Cedar records have fixed attributes and those keys depend on which command
ran, so the schema cannot type it. Policies may still read it:

```cedar
forbid (principal, action == SBX::Action::"exec", resource)
when { context.flagValues has user && context.flagValues.user == "root" };
```

## Protocol

A session is two connections to the same port, and the server tells them apart
by their opening bytes.

The first is an HTTP `POST /v1/session` carrying the caller's token in an
`Sbx-Warden-Token` header, answered with a single-use ticket that expires in 30
seconds. The credential travels as an HTTP header because that is the only place
a sandbox's egress proxy can substitute a secret, which is what lets the sandbox
hold a placeholder and never the token itself.

The second is the session: a 5-byte magic-and-version handshake, a `start` frame
carrying the ticket, the arguments and the terminal state, then length-prefixed
frames multiplexing stdin, stdout, stderr, window resizes and signals, ending
with an `exit` frame carrying the command's status. Frames are capped at 1 MiB.
Disconnecting kills the remote process group, so a dropped connection never
leaves work running unattended.

The split exists because the two need different things: substitution reaches
headers only, and a session needs a bidirectional stream that an HTTP request
through a proxy would buffer. A ticket is refused by the handshake and consumed
by the session, so it cannot be spent twice or traded for another.

## Releasing

Pushing a `v*` tag runs [GoReleaser](https://goreleaser.com) in CI, which builds
both binaries for linux, darwin and windows on amd64 and arm64, then publishes
one archive per binary plus `checksums.txt` to a GitHub release:

```bash
git tag -a v0.1.0 -m v0.1.0 && git push origin v0.1.0
```

Three things carry the version and have to move together before you tag: the
`version` and the installed release in `kit/sbx-warden/spec.yaml`, and the `#ref=`
in this file's kit references. `task kit:validate` fails when they disagree:

```bash
task kit:validate
```

Check the configuration and rehearse a build without publishing anything:

```bash
goreleaser check
goreleaser release --snapshot --clean --skip=publish
```
