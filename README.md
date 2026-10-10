# rust-mcp-remote

A Rust port of [mcp-remote](https://github.com/punkpeye/mcp-remote). It lets an MCP
client that only speaks stdio, such as Claude Desktop, Cursor or Windsurf, use a
remote MCP server over Streamable HTTP or SSE, including servers that need an OAuth
sign-in.

It is a single binary with no Node.js. It accepts the same flags as `mcp-remote` and
keeps its sign-in files in the same folder, so it can replace `npx mcp-remote` in an
existing config.

## Install

You need [Rust](https://rustup.rs).

```sh
cargo install --locked --force --git https://github.com/ravshansbox/rust-mcp-remote
```

This puts `rust-mcp-remote` and `mcp-remote-client` in `~/.cargo/bin`. `--force`
makes cargo rebuild even if this version is already installed, so the same command
also upgrades or reinstalls.

**Upgrade or reinstall:** run the `cargo install` command again.

**Uninstall:**

```sh
cargo uninstall rust-mcp-remote
rm -r ~/.mcp-auth/mcp-remote-v1          # optional: tokens, client registrations and logs
```

`~/.mcp-auth/mcp-remote-v1` is shared with npm `mcp-remote`, so leave it if you
still use that.

## Usage

Point your MCP client at the binary. MCP clients usually start servers without
your shell's `PATH`, so use the full path:

```json
{
  "mcpServers": {
    "remote-example": {
      "command": "/Users/you/.cargo/bin/rust-mcp-remote",
      "args": ["https://remote.mcp.server/mcp"]
    }
  }
}
```

On first use it opens your browser to sign in, and saves the tokens to
`~/.mcp-auth/mcp-remote-v1/`. Later runs reuse and renew them. If several copies
start at once for the same server, one signs in and the others wait for its
tokens.

To try a server from a terminal, `mcp-remote-client` signs in, lists the
server's tools and resources, and exits:

```sh
mcp-remote-client https://remote.mcp.server/mcp
```

Show help with `--help` and the version with `--version`.

## Flags

Put flags after the server URL. A number after the URL sets the OAuth callback
port. Without it, the port comes from the server URL, so every server gets a
stable port of its own.

| Flag | What it does |
| --- | --- |
| `--header "Name: value"` | Send a header with every request. Repeat for more |
| `--header-file <path>` | Read `Name: value` lines from a file |
| `--transport <strategy>` | `http-first` (default), `sse-first`, `http-only` or `sse-only` |
| `--protocol <mode>` | `legacy` (default) or `auto`, which also bridges to 2026-07-28 servers |
| `--allow-http` | Allow a plain HTTP server URL, for trusted private networks |
| `--host <name>` | Host in the OAuth callback URL (default `localhost`) |
| `--callback-path <path>` | Path of the OAuth callback (default `/oauth/callback`) |
| `--auth-timeout <seconds>` | How long to wait for the OAuth callback (default 30) |
| `--resource <url>` | The `resource` to ask a token for |
| `--disable-resource-parameter` | Leave `resource` out of OAuth requests |
| `--authorize-param key=value` | Add a parameter to the authorization request |
| `--static-oauth-client-metadata <json or @file>` | Client metadata to register with |
| `--static-oauth-client-info <json or @file>` | A pre-registered client, instead of registering one |
| `--client-metadata-url <https url>` | Use a Client ID Metadata Document as the client ID |
| `--use-id-token` | Send the ID token instead of the access token |
| `--device-code` | Sign in with the device grant, without a browser on this machine |
| `--client-credentials` | Sign in with the client credentials grant, without a user |
| `--token-endpoint <https url>` | Token endpoint for `--client-credentials`, skipping discovery |
| `--ignore-tool <pattern>` | Hide matching tools and block calls to them. `*` is a wildcard. Repeat for more |
| `--keep-alive` | Ping the server every 30 seconds so an idle session is not dropped |
| `--ping-interval <seconds>` | Ping period. Turns on keep-alive |
| `--connect-timeout <seconds>` | Limit on opening a connection |
| `--headers-timeout <seconds>` | Limit on waiting for response headers. `0` turns it off |
| `--body-timeout <seconds>` | Limit on a gap in a response body. `0` turns it off |
| `--ipv4` | Connect over IPv4 only |
| `--enable-proxy` | Use the `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` environment variables |
| `--disable-cookies` | Do not keep or send cookies the server sets |
| `--debug` | Write a detailed log to `~/.mcp-auth/mcp-remote-v1/<hash>_debug.log` |
| `--silent` | Print no log lines, except with `--debug` |

`${VAR}` in a header value or in `--static-oauth-client-info` is replaced with
the environment variable, so secrets can stay out of the config:

```json
"args": ["https://remote.mcp.server/mcp", "--header", "Authorization: Bearer ${AUTH_TOKEN}"],
"env": { "AUTH_TOKEN": "..." }
```

The [mcp-remote README](https://github.com/punkpeye/mcp-remote#readme) explains
each flag in more detail. Everything there applies here, with `npx mcp-remote`
replaced by the binary.

## Environment variables

| Variable | What it does |
| --- | --- |
| `MCP_REMOTE_CONFIG_DIR` | Folder for tokens and logs, instead of `~/.mcp-auth` |
| `NODE_EXTRA_CA_CERTS` | A PEM file of extra certificates to trust, for example a VPN's. The name is kept from `mcp-remote` |

## Differences from mcp-remote

- No default network timeouts. `mcp-remote` gives up after 10 seconds when
  connecting, and after 300 seconds waiting for headers or between body chunks.
  Here, each limit applies only when you set its flag.
- `--connect-timeout`, `--headers-timeout`, `--body-timeout`, `--ipv4` and
  `--enable-proxy` apply to every request. In `mcp-remote`, some discovery
  requests ignore them.
- Certificates come from the system trust store plus `NODE_EXTRA_CA_CERTS`.
- Less memory. Proxying the GitHub MCP server (`https://api.githubcopilot.com/mcp`)
  on macOS, idle after `initialize` and `tools/list`:

  | Command | Resident memory |
  | --- | --- |
  | `rust-mcp-remote` | 16 MiB |
  | `node` running `mcp-remote` 0.14.3 (Node.js 24) | 130 MiB |
  | `npx -y mcp-remote` (adds the `npm exec` process) | 248 MiB |

  A client config with five servers uses about 80 MiB instead of about 1.2 GiB.

## Limits

- Tested on macOS only. Linux and Windows, including opening the browser on
  Windows, are untested.

## Development

Before each commit, run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
and `cargo test`. Each source module has one test binary in `tests/<module>/`.

## Licence

MIT. See [LICENSE](LICENSE).
