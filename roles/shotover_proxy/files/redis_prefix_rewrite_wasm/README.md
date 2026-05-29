# Generic Valkey/Redis Key Prefix Rewrite WASM Transform for Shotover Proxy

This directory contains a **fully generic, configuration-driven** WebAssembly (WASM) transform for Shotover Proxy to handle transparent key prefix translation/re-writing.

## Problem Context
1. **Cluster Clustering Slot Restriction:** In a Valkey/Redis Cluster, keys are assigned to 16,384 hash slots. Multi-key operations, transactions (`MULTI`/`EXEC`), and certain scripts require all keys involved to hash to the *exact same* slot, otherwise throwing a `CROSSSLOT` error.
2. **Hashtag Solution:** To force keys into the same slot, Redis supports "hashtags" (e.g., `{authelia-session}.<session_id>`). Only the string inside the curly braces is hashed.
3. **Application Limitations:** Many upstream applications do not allow modifying the key prefix (they hardcode keys starting with a static string like `authelia-session.`). This prevents using standard versions of these applications directly with a Valkey cluster without custom patching, as multi-key transactions trigger `CROSSSLOT` errors.

## Solution
This generic Shotover WASM transform intercepts Valkey traffic and translates key prefixes on-the-fly based on YAML configuration rules specified in your `topology.yaml`:
1. **Inbound Requests:** Intercepts Redis commands and rewrites keys matching configured target prefixes (e.g. `authelia-session.<id>` to `{authelia-session}.<id>`).
2. **Outbound Responses:** Intercepts Valkey responses and rewrites keys back to their standard, un-bracketed form *only* for the `KEYS` and `SCAN` commands, and any embedded `Error`/`Status` messages. This keeps the translation completely transparent to your applications.
3. **Payload Safety:** It explicitly avoids touching the values/payloads returned by `GET` or `MGET` commands, preventing any risk of JSON or binary data corruption.

## Topology Configuration
You can define any number of translation pairs directly inside the Shotover `topology.yaml` configuration (via Ansible variables):

```yaml
        chain:
          - Wasm:
              wasm_path: "/etc/shotover/topology/redis_prefix_rewrite_wasm.wasm"
              config:
                translations:
                  - from: "authelia-session."
                    to: "{authelia-session}."
                  - from: "authelia-session:"
                    to: "{authelia-session}:"
                  - from: "other-app:"
                    to: "{other-app}:"
```

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
The `shotover_proxy` role handles compilation (locally on the controller by default, or optionally on the proxy), hashing the source directory to maintain a clean version cache, uploading the artifact, symlinking it to `/etc/shotover/topology/redis_prefix_rewrite_wasm.wasm`, and restarting Shotover.
