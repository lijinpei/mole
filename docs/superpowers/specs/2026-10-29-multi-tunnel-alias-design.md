# Multi-server, multi-kind aliases

## Goal

Let one alias forward through several ssh servers at once, each carrying any mix
of local, remote, dynamic and reverse-dynamic forwards, started and stopped as a
single mole instance.

Today an alias holds one `server`, one `type`, and `source`/`destination` lists
of that type.

## Alias file format

Multi-tunnel aliases are written by hand in `~/.mole/<name>.toml`. `mole add
alias` keeps writing the existing flat format.

```toml
# process-wide
verbose = false
detach = true
rpc = true
rpc-address = "127.0.0.1:0"

# defaults inherited by every tunnel
key = "~/.ssh/id_ed25519"
connection-retries = 3

[[tunnels]]
server = "me@bastion-a"
  [[tunnels.forwards]]
  type = "local"
  source = [":8080"]
  destination = ["db:5432"]
  [[tunnels.forwards]]
  type = "dynamic"
  source = [":1080"]

[[tunnels]]
server = "me@bastion-b:2222"
key = "~/.ssh/other"
  [[tunnels.forwards]]
  type = "remote"
  source = ["0.0.0.0:9000"]
  destination = ["127.0.0.1:3000"]
```

### Settings

| Level | Keys |
|---|---|
| Process-wide (top level only) | `verbose`, `detach`, `rpc`, `rpc-address` |
| Tunnel (top level is the default, `[[tunnels]]` overrides) | `key`, `ssh-agent`, `config`, `insecure`, `timeout`, `keep-alive-interval`, `connection-retries`, `wait-and-retry`, `socks-auth` |
| Tunnel only | `server` (required), `forwards` (at least one) |
| Forward | `type` (required), `source`, `destination` |

- A tunnel setting missing from both levels takes the CLI default: `timeout`
  3s, `keep-alive-interval` 10s, `connection-retries` 3, `wait-and-retry` 3s,
  `config` `$HOME/.ssh/config`, `insecure` false.
- `source`/`destination` follow today's rules for their `type`: extra sources
  are dropped, missing sources get `127.0.0.1:0`, dynamic and reverse-dynamic
  take no destination, and a forward with neither reads the matching
  `LocalForward`/`RemoteForward`/`DynamicForward` of that server from the ssh
  config file.

### Compatibility

- A flat alias (top-level `server`/`type`/`source`/`destination`, no
  `tunnels`) loads, starts, and shows exactly as today.
- `mole show alias` of a flat alias prints the same output as today.
- `mole start local|remote|dynamic|reverse-dynamic` is unchanged.

### Validation (fails `mole start alias` before anything connects)

- `tunnels` together with any of top-level `server`, `type`, `source`,
  `destination`.
- A tunnel without `server`.
- A tunnel without forwards.
- A forward with a missing or unknown `type`.
- A dynamic or reverse-dynamic forward with a destination (existing rule).

## Runtime behavior

- One process per alias, as today: one id, one pid file, one rpc server, one
  log. `mole stop <alias>` stops everything.
- Each `[[tunnels]]` entry is one ssh connection with its own keep-alive and
  reconnection loop. All of its forwards share that connection.
- When a tunnel ends for good (retries exhausted, a local or dynamic source
  endpoint taken), the failure is logged with its server and the other tunnels
  keep running. `mole start alias` returns once every tunnel has ended, exiting
  with status 1 if any of them failed.
- `--verbose`, `--detach` and `--insecure` given to `mole start alias` override
  the file; `--insecure` applies to every tunnel.
- `mole show instances` of a multi-tunnel instance lists each tunnel's server
  and forwards, with the source endpoints actually bound (a `:0` source shows
  the assigned port). The socks credentials are left out, as today.

## Code changes

### `tunnel`

- `Forward{Type string; Source, Destination []string}` and
  `NewWithForwards(server *Server, forwards []Forward, config string)`, which
  builds the channels of every forward through `buildSSHChannels` and validates
  each type. `New(tunnelType, server, source, destination, config)` becomes a
  wrapper around it.
- `startChannel` switches on `channel.ChannelType` instead of `t.Type`.
- `Listen` reports which channel failed; `connect` retries a listen failure
  only when that channel listens on the ssh server (remote, reverse-dynamic),
  and ends the tunnel otherwise, as today.
- `Tunnel.Type` keeps the kind when every channel shares it and is empty
  otherwise; nothing dispatches on it anymore.

### `alias`

- `Alias.Tunnels []Tunnel`, where `Tunnel` carries `Server`, the overridable
  tunnel settings and `Forwards []Forward{Type, Source, Destination}`.
  Overrides whose zero value is meaningful are pointers (`Insecure *bool`,
  `ConnectionRetries *int`); string settings use `""` for "inherit".
- `omitempty` on `type`, `server`, `source`, `destination` and `tunnels`, so a
  multi-tunnel alias does not show empty flat keys. A flat alias keeps showing
  all of them, since they are set.
- `Get` applies the CLI defaults to top-level tunnel settings missing from the
  file (`connection-retries` is detected through the toml metadata, since 0
  means "never give up").

### `mole`

- `Configuration.Tunnels []TunnelConfiguration`, each with the server, the
  resolved connection settings and its forwards (toml key `tunnels`,
  `omitempty`).
- `Merge` resolves a multi-tunnel alias into `Tunnels` (inheritance, defaults,
  `--insecure`) and enforces the validation rules. A flat alias leaves
  `Tunnels` empty and fills the flat fields as today.
- `Client.Tunnel` becomes `Client.Tunnels []*tunnel.Tunnel`. `Start` creates
  every tunnel first, one after the other, so key passphrase prompts never
  interleave; any creation error stops the instance before anything connects.
  It then starts all tunnels concurrently, logs each failure with its server,
  waits for all of them, and returns `errors.Join` of the failures.
- `Runtime()` keeps today's flat output when `Conf.Tunnels` is empty and fills
  each tunnel's forwards with the bound sources otherwise.

### Docs

- `docs/index.md`: a section on multi-tunnel aliases with the example above.
- `CHANGELOG.md`: an "Added" entry under Unreleased.

## Testing

Written test-first, using the in-process ssh test server the `tunnel` and
`mole` tests already rely on.

1. `alias`: a multi-tunnel file decodes into `Tunnels`, shows without empty
   flat keys, and round-trips; existing flat fixtures pass unchanged.
2. `mole` merge: inheritance, per-tunnel overrides, defaults, `--insecure`, and
   each validation error.
3. `mole` runtime: a multi-tunnel instance reports per-tunnel forwards with
   bound sources; flat output tests pass unchanged.
4. `tunnel`: one tunnel serving local, dynamic and remote channels at once; a
   taken local source ends the tunnel; a remote listen failure is retried.
5. `mole` client: two tunnels where one fails at start keep the other
   forwarding, and `Start` returns only after both have ended, with the joined
   error.

## Out of scope

- CLI commands to build or edit multi-tunnel aliases.
- Stopping, restarting or inspecting a single tunnel of a running instance.
- Sharing one ssh connection between tunnels naming the same server.
