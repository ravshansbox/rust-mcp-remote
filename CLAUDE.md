# Decisions for the Rust port of ../mcp-remote

These answer the open questions in the gnhf notes (iterations 144-146). They are final; do not ask again.

1. HTTP and runtime: use reqwest + tokio (async). Add both to Cargo.toml and start porting the transport-bound parts: fetchWithMcpHeaders and the cookie wrappers, discoverOAuthServerInfo, connectToRemoteServer, setupOAuthCallbackServerWithLongPoll, setupSignalHandlers, mcpProxy, coordination.ts, client-diagnostics.ts, client.ts, proxy.ts.
2. MCP SDK: hand-port the parts of @modelcontextprotocol/sdk that mcp-remote uses (the client, the SSE, streamable HTTP and stdio transports, the OAuth auth() flow), working on raw JSON-RPC values. Do not use rmcp or another MCP crate. The SDK source is not in ../mcp-remote; look for it in the npx cache (~/.npm/_npx/*/node_modules/@modelcontextprotocol/) before relying on memory.
3. acquireConfigLease race: fix it. Write the lease to a temp file, then hard-link it into place, so a reader never sees an empty lease file. Differing from TS here is approved.

# Working rules

- Test layout (done in iteration 147): keep one test binary per source module under tests/<module>/. Do not add new top-level files in tests/.
- Step size: port one whole function or module per iteration, not the smallest possible piece. The prompt's "smallest possible steps" is superseded by this rule.
- Validation: each iteration, run clippy (-D warnings), cargo fmt, and only the tests of the modules you touched. Run the full `cargo test` every 5th iteration and whenever you touch shared code.
- Done means: every function in ../mcp-remote/src is ported and wired into main (OAuth sign-in with the browser callback, SSE fallback, coordination, keep-alive, protocol mode `auto`, and client.ts), every TS test file has a Rust counterpart, and the binary signs in to and proxies a real MCP server that requires OAuth.
- OAuth end-to-end check: the SDK in ~/.npm/_npx/7600f439cbbb35be/node_modules/@modelcontextprotocol/sdk/dist/esm/ has a demo OAuth server (examples/server/demoInMemoryOAuthProvider.js plus server/auth/) to put in front of a streamable HTTP MCP server. Drive the browser step with the authorize URL directly (e.g. curl following redirects to the callback) rather than a real browser.
