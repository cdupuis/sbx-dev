# sbx-dev

Exposes the host's [`sbx`](https://github.com/docker/sandboxes) CLI over TCP so
an agent inside a sandbox can drive Docker Sandboxes on the host.

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
> A coding agent acts on what it reads — a repository, an issue, a web page — so
> assume anything it reads can reach your host. Run this only where that is
> acceptable, and narrow it with `--allow-command`. See [Security](#security).

Two binaries:

| Binary    | Runs on           | Role                                                          |
| --------- | ----------------- | ------------------------------------------------------------- |
| `sbx-dev` | the host          | Listens on loopback and executes the real `sbx` per request.  |
| `sbx`     | inside a sandbox  | Forwards its arguments to `sbx-dev` and relays stdio.         |

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
curl -fsSL https://raw.githubusercontent.com/cdupuis/sbx-dev/main/install.sh | sh -s -- --server
```

On Windows, in PowerShell:

```powershell
$env:SBX_DEV_COMPONENTS = 'server'
irm https://raw.githubusercontent.com/cdupuis/sbx-dev/main/install.ps1 | iex
```

Then [run it](#run-the-server-on-the-host); the first start writes the token the
client needs. Dropping `--server` installs both binaries, which is only worth
doing if you want a client on the host too, for testing against the server
directly.

### The client, in a sandbox

Use the kit. It installs the client while a sandbox is being created, allows the
egress it needs, and points it at the host, so there is nothing to install inside
the sandbox afterwards, and nothing to clone to get it:

```bash
export SBX_DEV_TOKEN=$(cat ~/.sbx-dev/token)
sbx create shell . \
  --kit 'git+https://github.com/cdupuis/sbx-dev.git#ref=v0.2.0&dir=kit/sbx-dev' \
  --env SBX_DEV_TOKEN
```

Keep the reference quoted, or the shell reads the `&` before `dir=` as a request
to run the command in the background.

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
or `~/.local/bin` otherwise (`%LOCALAPPDATA%\sbx-dev\bin` on Windows). They never
invoke `sudo`, since a piped script has no terminal to prompt on.

Because the client is called `sbx`, installing it where a real Docker Sandboxes
CLI already lives would shadow that CLI. The installers detect this and skip the
client rather than break your `sbx`; use `--force` or `--dir` if you meant it.

| Option                  | Environment variable    | Purpose                          |
| ----------------------- | ----------------------- | -------------------------------- |
| `--client` / `--server` | `SBX_DEV_COMPONENTS`    | Which binaries to install.       |
| `--version VERSION`     | `SBX_DEV_VERSION`       | Install a specific release.      |
| `--dir DIRECTORY`       | `SBX_DEV_INSTALL_DIR`   | Where to install.                |
| `--force`               | —                       | Replace a foreign `sbx`.         |
| —                       | `SBX_DEV_DOWNLOAD_BASE` | Mirror serving release archives. |

Piping to `iex` cannot pass parameters, so the Windows installer reads the
environment variables above.

## Build from source

```bash
task build                 # ./bin/sbx-dev and ./bin/sbx for this host
task build:client:all      # linux/amd64 and linux/arm64 clients for sandboxes
```

## Run the server on the host

```bash
sbx-dev --addr 127.0.0.1:7391
```

On first start it generates a shared token at `~/.sbx-dev/token` and prints the
three lines you need to set up a client.

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
pinned client release into `/usr/local/bin`, exports `SBX_DEV_ADDR`, and allows
the egress those need. It leaves out the token deliberately.

Kit environment values are literal, so a token in the kit would be a secret
committed to a repository, and the kit credential mechanism cannot help: it
injects secrets into HTTP headers, which does nothing for a raw TCP protocol. A
bare `--env SBX_DEV_TOKEN` takes the value from your shell instead.

The kit allows exactly one host port, `localhost:7391`, so the sandbox can reach
the server and nothing else on your host — not even another port on the same
host. Read that as tidiness rather than containment: the one port it does reach
is the host's `sbx` CLI, and the policy the kit installs is itself something the
sandbox can rewrite through that port. `--allow-command` on the server is what
constrains this; the allow list is not.

Running the server elsewhere means changing both `SBX_DEV_ADDR` and the
`permissions.network.allow` entry in the kit, because a rule naming one port
does not match another.

Because the kit pins the client release it installs, its `version` tracks the
client version rather than moving independently.

The `#ref=` in the reference pins the kit the same way, so a sandbox created from
it months from now still gets this kit installing this client. Point it at
`#ref=main` to follow the branch instead, or at a commit SHA for a reference that
cannot move at all — a tag can be repointed, a SHA cannot. A checkout of this
repository can also name the kit by path, as `./kit/sbx-dev`, which is what
`task kit:validate` does while you are changing the kit itself.

### Adding it to a sandbox that already exists

A sandbox that predates the kit does not need the by-hand route: `sbx kit add`
recreates it with the kit applied, keeping kit-owned volumes and workspace data.

```bash
sbx kit add my-sandbox 'git+https://github.com/cdupuis/sbx-dev.git#ref=v0.2.0&dir=kit/sbx-dev'
```

The swap preserves the sandbox's environment, so one created with
`--env SBX_DEV_TOKEN` keeps its token. One created without it has no token to
keep, and a container's environment is fixed when it is created, so put the token
in the file the client falls back to instead: it reads `~/.sbx-dev/token` inside
the sandbox whenever `SBX_DEV_TOKEN` is unset.

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
curl -fsSL https://raw.githubusercontent.com/cdupuis/sbx-dev/main/install.sh | sh -s -- --client
```

That lands in `~/.local/bin`, which is writable and already first on `PATH` in
the standard sandbox images, so pass no `--dir`: `/usr/local/bin` is root-owned
and the agent cannot write to it.

Or copy a locally built binary in, which needs no extra egress:

```bash
task install:client SANDBOX=my-sandbox     # or: sbx cp ./bin/sbx-linux-arm64 my-sandbox:/usr/local/bin/sbx
```

Then, inside the sandbox:

```bash
export SBX_DEV_ADDR=host.docker.internal:7391
export SBX_DEV_TOKEN=<token from ~/.sbx-dev/token on the host>
sbx ls
```

## Configuration

The client takes no flags of its own, so that every flag reaches the real CLI.
It reads:

| Variable              | Default                        | Purpose                                        |
| --------------------- | ------------------------------ | ---------------------------------------------- |
| `SBX_DEV_ADDR`        | `host.docker.internal:7391`    | Server address.                                |
| `SBX_DEV_TOKEN`       | —                              | Shared token; preferred over the file.         |
| `SBX_DEV_TOKEN_FILE`  | `~/.sbx-dev/token`             | Token file, read when `SBX_DEV_TOKEN` is unset. |
| `SBX_DEV_FORWARD_ENV` | —                              | Comma-separated env var names to send along.   |
| `SBX_DEV_NO_TTY`      | —                              | Set to any value to suppress PTY allocation.   |
| `SBX_DEV_PRINT_VERSION` | —                            | Print the client's version and exit.           |

Environment variables are not forwarded by default; name them explicitly in
`SBX_DEV_FORWARD_ENV` when a command needs them. The child process otherwise
inherits the server's environment.

Server flags: `--addr`, `--sbx`, `--token-file`, `--workdir`, `--allow-command`,
`--allow-any-bind`, `--verbose`, `--version`. Run `sbx-dev --help` for details.

The client reports its own version through `SBX_DEV_PRINT_VERSION` rather than a
flag, because every argument belongs to the remote CLI.

## Security

The token is the entire boundary. Anyone holding it can do everything in the
warning at the top of this file, so treat it like an SSH key: it lives in a
`0600` file, and the server compares it in constant time. Loopback binding
limits *who* can present a token, not what a token permits.

`--allow-command` is the one control that reduces what a token permits, by
restricting sessions to named subcommands and rejecting everything else:

```bash
sbx-dev --allow-command ls,ps,logs
```

Choose that list as if the caller were hostile. It narrows the blast radius
rather than removing it: `ls` still discloses every sandbox name and host
workspace path, and `logs` still discloses whatever the agents there have
printed. The escapes above need `create`, `exec` and `policy`, so a list that
omits all three is the difference between reconnaissance and host access.

## Protocol

A session is one TCP connection: a 5-byte magic-and-version handshake, a `start`
frame carrying the arguments and terminal state, then length-prefixed frames
multiplexing stdin, stdout, stderr, window resizes and signals, ending with an
`exit` frame carrying the command's status. Frames are capped at 1 MiB.
Disconnecting kills the remote process group, so a dropped connection never
leaves work running unattended.

## Releasing

Pushing a `v*` tag runs [GoReleaser](https://goreleaser.com) in CI, which builds
both binaries for linux, darwin and windows on amd64 and arm64, then publishes
one archive per binary plus `checksums.txt` to a GitHub release:

```bash
git tag -a v0.1.0 -m v0.1.0 && git push origin v0.1.0
```

Three things carry the version and have to move together before you tag: the
`version` and the installed release in `kit/sbx-dev/spec.yaml`, and the `#ref=`
in this file's kit references. `task kit:validate` fails when they disagree:

```bash
task kit:validate
```

Check the configuration and rehearse a build without publishing anything:

```bash
goreleaser check
goreleaser release --snapshot --clean --skip=publish
```
