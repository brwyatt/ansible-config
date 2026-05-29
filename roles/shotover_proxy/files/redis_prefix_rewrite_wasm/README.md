# Valkey/Redis Key Prefix Rewrite WASM Transform for Shotover Proxy

This directory contains a custom WebAssembly (WASM) transform for Shotover Proxy to handle transparent key prefix translation for Authelia.

## Problem Context
1. **Cluster Clustering Slot Restriction:** In a Valkey/Redis Cluster, keys are assigned to 16,384 hash slots. Multi-key operations, transactions (`MULTI`/`EXEC`), and certain scripts require all keys involved to hash to the *exact same* slot, otherwise throwing a `CROSSSLOT` error.
2. **Hashtag Solution:** To force keys into the same slot, Redis supports "hashtags" (e.g., `{authelia-session}.<session_id>`). Only the string inside the curly braces is hashed.
3. **Upstream Authelia Limitation:** Upstream Authelia does not allow modifying the key prefix (it hardcodes keys starting with `authelia-session.`). This prevents using standard Authelia directly with a Valkey cluster without custom patching, as multi-key transactions can trigger `CROSSSLOT` errors.

## Solution
This Shotover WASM transform intercepts Valkey traffic and translates key prefixes on-the-fly:
1. **Inbound Requests:** Intercepts Redis commands and rewrites keys matching `authelia-session.<id>` or `authelia-session:<id>` to `{authelia-session}.<id>` or `{authelia-session}:<id>`.
2. **Outbound Responses:** Intercepts Valkey responses and rewrites keys back to their standard, un-bracketed form *only* for the `KEYS` and `SCAN` commands, and any embedded `Error`/`Status` messages. This keeps the translation completely transparent to Authelia.
3. **Payload Safety:** It explicitly avoids touching the values/payloads returned by `GET` or `MGET` commands, preventing any risk of JSON or binary data corruption.

## Compilation Instructions
To build the WebAssembly module, you need the Rust toolchain with the WASM target installed:

```bash
# Install the WASM compilation target
rustup target add wasm32-wasi

# Build the release target
cargo build --target wasm32-wasi --release
```

Once built, the `.wasm` file will be located at:
`target/wasm32-wasi/release/redis_prefix_rewrite_wasm.wasm`

## Ansible Deployment
Deploy this `.wasm` file to your Shotover proxies at `/etc/shotover/topology/redis_prefix_rewrite_wasm.wasm` and update the `shotover_topology` configuration.
