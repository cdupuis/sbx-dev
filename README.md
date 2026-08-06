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

## Build

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

Install the client and point it at the host:

```bash
task install:client SANDBOX=my-sandbox     # or: sbx cp ./bin/sbx-linux-arm64 my-sandbox:/usr/local/bin/sbx
```

Then, inside the sandbox:

```bash
export SBX_DEV_ADDR=host.docker.internal:7391
export SBX_DEV_TOKEN=<token from ~/.sbx-dev/token on the host>
sbx ls
```

Install the client somewhere that does **not** shadow a real `sbx` on the host's
`PATH`; it is only meant to be the `sbx` inside a sandbox.

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

Environment variables are not forwarded by default; name them explicitly in
`SBX_DEV_FORWARD_ENV` when a command needs them. The child process otherwise
inherits the server's environment.

Server flags: `--addr`, `--sbx`, `--token-file`, `--workdir`, `--allow-command`,
`--allow-any-bind`, `--verbose`. Run `sbx-dev --help` for details.

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
