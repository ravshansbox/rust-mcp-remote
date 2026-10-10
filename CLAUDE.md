# Decisions for the Rust port of ../mcp-remote

These answer the open questions in the gnhf notes (iterations 144-146). They are final; do not ask again.

1. HTTP and runtime: use reqwest + tokio (async). Add both to Cargo.toml and start porting the transport-bound parts: fetchWithMcpHeaders and the cookie wrappers, discoverOAuthServerInfo, connectToRemoteServer, setupOAuthCallbackServerWithLongPoll, setupSignalHandlers, mcpProxy, coordination.ts, client-diagnostics.ts, client.ts, proxy.ts.
2. MCP SDK: hand-port the parts of @modelcontextprotocol/sdk that mcp-remote uses (the client, the SSE, streamable HTTP and stdio transports, the OAuth auth() flow), working on raw JSON-RPC values. Do not use rmcp or another MCP crate. The SDK source is not in ../mcp-remote; look for it in the npx cache (~/.npm/_npx/*/node_modules/@modelcontextprotocol/) before relying on memory.
3. acquireConfigLease race: fix it. Write the lease to a temp file, then hard-link it into place, so a reader never sees an empty lease file. Differing from TS here is approved.

# Working rules

- First task: merge tests/*.rs into one test file per source module (or move them into `#[cfg(test)]` modules in src/). Every file in tests/ builds as its own test binary, and ~140 of them make `cargo test` take ~10 minutes. Keep every existing test.
- Step size: port one whole function or module per iteration, not the smallest possible piece. The prompt's "smallest possible steps" is superseded by this rule.
- Validation: each iteration, run clippy (-D warnings), cargo fmt, and only the tests of the modules you touched. Run the full `cargo test` every 5th iteration and whenever you touch shared code.
- Done means: the rust binary proxies a real MCP server over stdio end-to-end, and all tests pass.
