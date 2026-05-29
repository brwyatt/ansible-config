use anyhow::Result;
use shotover_wasm::frame::{Frame, RedisValue};
use shotover_wasm::transform::{Message, Transform, TransformContext, TransformResult};

/// A custom Shotover transform that transparently translates Valkey/Redis keys
/// for Authelia sessions to force them into a single hash slot (`{authelia-session}`).
///
/// Standard Authelia uses keys like `authelia-session.xxxx` or `authelia-session:xxxx`.
/// If run on a cluster, this can cause CROSSSLOT errors because different keys map to
/// different nodes.
///
/// This transform rewrites:
/// - Requests: `authelia-session.<id>` -> `{authelia-session}.<id>` (and colons)
/// - Responses (for KEYS and SCAN commands, and Error/Status messages):
///   `{authelia-session}.<id>` -> `authelia-session.<id>` (and colons)
pub struct RedisPrefixRewrite;

impl Transform for RedisPrefixRewrite {
    fn transform(&self, context: &mut TransformContext, mut messages: Vec<Message>) -> TransformResult {
        // 1. Keep track of the commands in the current batch to safely rewrite responses.
        let mut request_commands = Vec::with_capacity(messages.len());

        // 2. Process each request message in the batch
        for message in &mut messages {
            let mut cmd_name = String::new();
            
            if let Some(Frame::Redis(value)) = message.frame_mut() {
                if let RedisValue::Array(args) = value {
                    if !args.is_empty() {
                        // Extract command name (e.g. GET, SET)
                        if let RedisValue::BulkString(bytes) = &args[0] {
                            if let Ok(s) = std::str::from_utf8(bytes) {
                                cmd_name = s.to_ascii_uppercase();
                            }
                        }

                        // Rewrite keys for the command if we found its name
                        if !cmd_name.is_empty() {
                            rewrite_request_keys(&cmd_name, args);
                        }
                    }
                }
                message.invalidate(); // Mark message as modified so Shotover serializes the changes
            }
            request_commands.push(cmd_name);
        }

        // 3. Pass the modified requests down the transform chain (to the Valkey cluster sink)
        let mut responses = context.call_next(messages)?;

        // 4. Process the responses from the Valkey cluster
        for (i, response) in responses.iter_mut().enumerate() {
            let corresponding_cmd = request_commands.get(i).cloned().unwrap_or_default();
            
            if let Some(Frame::Redis(value)) = response.frame_mut() {
                // To avoid corrupting binary or JSON data in GET / MGET values,
                // we ONLY rewrite:
                // - Response arrays for KEYS and SCAN commands (which return key lists)
                // - Status or Error messages (which might include the key in error reports)
                rewrite_response_keys(&corresponding_cmd, value);
                response.invalidate(); // Mark response as modified
            }
        }

        Ok(responses)
    }
}

/// Rewrites key arguments in Valkey requests
fn rewrite_request_keys(command: &str, args: &mut [RedisValue]) {
    match command {
        "GET" | "EXPIRE" | "TTL" | "SET" | "SETEX" => {
            // Key is at index 1
            if args.len() > 1 {
                rewrite_key_value(&mut args[1]);
            }
        }
        "DEL" | "EXISTS" | "MGET" => {
            // All arguments from index 1 to N are keys
            for key_arg in args.iter_mut().skip(1) {
                rewrite_key_value(key_arg);
            }
        }
        "MSET" => {
            // MSET key value [key value ...] (keys at 1, 3, 5, ...)
            let mut i = 1;
            while i < args.len() {
                rewrite_key_value(&mut args[i]);
                i += 2;
            }
        }
        "KEYS" => {
            // Index 1 is the pattern
            if args.len() > 1 {
                rewrite_key_value(&mut args[1]);
            }
        }
        "SCAN" => {
            // SCAN cursor [MATCH pattern] ...
            // Search for "MATCH" and rewrite the next argument
            let mut i = 1;
            while i < args.len() - 1 {
                if let RedisValue::BulkString(bytes) = &args[i] {
                    if let Ok(arg_str) = std::str::from_utf8(bytes) {
                        if arg_str.to_ascii_uppercase() == "MATCH" {
                            rewrite_key_value(&mut args[i + 1]);
                            break;
                        }
                    }
                }
                i += 1;
            }
        }
        _ => {}
    }
}

/// Helper to rewrite a single key value
fn rewrite_key_value(value: &mut RedisValue) {
    if let RedisValue::BulkString(bytes) = value {
        if let Ok(key_str) = std::str::from_utf8(bytes) {
            // Convert 'authelia-session.' to '{authelia-session}.' and 'authelia-session:' to '{authelia-session}:'
            if key_str.starts_with("authelia-session.") {
                let rewritten = key_str.replace("authelia-session.", "{authelia-session}.");
                *bytes = bytes::Bytes::from(rewritten);
            } else if key_str.starts_with("authelia-session:") {
                let rewritten = key_str.replace("authelia-session:", "{authelia-session}:");
                *bytes = bytes::Bytes::from(rewritten);
            }
        }
    }
}

/// Rewrites key arguments/values in responses from Valkey back to standard names
fn rewrite_response_keys(command: &str, value: &mut RedisValue) {
    match value {
        RedisValue::BulkString(bytes) => {
            // If the command is KEYS, every BulkString returned is a key
            if command == "KEYS" {
                revert_key_value(bytes);
            }
        }
        RedisValue::Array(items) => {
            if command == "KEYS" {
                // Array of key names
                for item in items {
                    if let RedisValue::BulkString(bytes) = item {
                        revert_key_value(bytes);
                    }
                }
            } else if command == "SCAN" {
                // SCAN returns: [cursor_string, Array of keys]
                if items.len() > 1 {
                    if let RedisValue::Array(keys_array) = &mut items[1] {
                        for item in keys_array {
                            if let RedisValue::BulkString(bytes) = item {
                                revert_key_value(bytes);
                            }
                        }
                    }
                }
            }
        }
        RedisValue::Status(status_str) => {
            // Revert any keys embedded in status messages
            if status_str.contains("{authelia-session}.") || status_str.contains("{authelia-session}:") {
                *status_str = status_str
                    .replace("{authelia-session}.", "authelia-session.")
                    .replace("{authelia-session}:", "authelia-session:");
            }
        }
        RedisValue::Error(err_str) => {
            // Revert any keys embedded in error messages
            if err_str.contains("{authelia-session}.") || err_str.contains("{authelia-session}:") {
                *err_str = err_str
                    .replace("{authelia-session}.", "authelia-session.")
                    .replace("{authelia-session}:", "authelia-session:");
            }
        }
        _ => {}
    }
}

/// Helper to revert a single key value
fn revert_key_value(bytes: &mut bytes::Bytes) {
    if let Ok(key_str) = std::str::from_utf8(bytes) {
        if key_str.starts_with("{authelia-session}.") {
            let reverted = key_str.replace("{authelia-session}.", "authelia-session.");
            *bytes = bytes::Bytes::from(reverted);
        } else if key_str.starts_with("{authelia-session}:") {
            let reverted = key_str.replace("{authelia-session}:", "authelia-session:");
            *bytes = bytes::Bytes::from(reverted);
        }
    }
}

// Register the custom transform with Shotover WASM SDK
shotover_wasm::export_transform!(RedisPrefixRewrite);
