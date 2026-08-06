# sbx-dev

Exposes the host's [`sbx`](https://github.com/docker/sandboxes) CLI over TCP so
an agent inside a sandbox can drive Docker Sandboxes on the host.

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

On Linux or macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/cdupuis/sbx-dev/main/install.sh | sh
```

On Windows, in PowerShell:

```powershell
irm https://raw.githubusercontent.com/cdupuis/sbx-dev/main/install.ps1 | iex
```

Both binaries are installed by default. Add `--server` or `--client` to pick one
— on your host you only need the server, and inside a sandbox only the client:

```bash
curl -fsSL https://raw.githubusercontent.com/cdupuis/sbx-dev/main/install.sh | sh -s -- --server
```

The installers download the latest GitHub release, verify it against the
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

Allow the port in the sandbox network policy. The rule must name `localhost`,
not `host.docker.internal`, because the proxy rewrites the request host before
evaluating policy while rules are matched verbatim:

```bash
sbx policy allow network localhost:7391
```

Get the client into the sandbox. Either run the installer inside it, which needs
`raw.githubusercontent.com` and `objects.githubusercontent.com` allowed in the
sandbox's policy:

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

Anyone holding the token can run any `sbx` command on the host, and `sbx exec`
alone is equivalent to arbitrary code execution there. The token is the only
boundary, so treat it like an SSH key: it lives in a `0600` file, and the server
compares it in constant time.

Narrow the blast radius with `--allow-command`, which restricts sessions to
named subcommands:

```bash
sbx-dev --allow-command ls,ps,logs
```

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

Check the configuration and rehearse a build without publishing anything:

```bash
goreleaser check
goreleaser release --snapshot --clean --skip=publish
```
