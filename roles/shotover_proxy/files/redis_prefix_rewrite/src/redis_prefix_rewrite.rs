use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use shotover::frame::{Frame, MessageType, ValkeyFrame};
use shotover::message::{MessageIdSet, Messages};
use shotover::transforms::{
    ChainState, Transform, TransformBuilder, TransformConfig, TransformContextConfig,
};
use shotover::transforms::{DownChainProtocol, TransformContextBuilder, UpChainProtocol};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Translation {
    pub from: String,
    pub to: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct RedisPrefixRewriteConfig {
    pub translations: Vec<Translation>,
}

const NAME: &str = "RedisPrefixRewrite";

#[typetag::serde(name = "RedisPrefixRewrite")]
#[async_trait(?Send)]
impl TransformConfig for RedisPrefixRewriteConfig {
    async fn get_builder(
        &self,
        _transform_context: TransformContextConfig,
    ) -> Result<Box<dyn TransformBuilder>> {
        Ok(Box::new(RedisPrefixRewriteBuilder {
            translations: self.translations.clone(),
        }))
    }

    fn up_chain_protocol(&self) -> UpChainProtocol {
        UpChainProtocol::MustBeOneOf(vec![MessageType::Valkey])
    }

    fn down_chain_protocol(&self) -> DownChainProtocol {
        DownChainProtocol::SameAsUpChain
    }
}

pub struct RedisPrefixRewriteBuilder {
    translations: Vec<Translation>,
}

impl TransformBuilder for RedisPrefixRewriteBuilder {
    fn build(&self, _transform_context: TransformContextBuilder) -> Box<dyn Transform> {
        Box::new(RedisPrefixRewrite {
            request_commands: Vec::new(),
            translations: self.translations.clone(),
        })
    }

    fn get_name(&self) -> &'static str {
        NAME
    }
}

pub struct RedisPrefixRewrite {
    request_commands: Vec<String>,
    translations: Vec<Translation>,
}

#[async_trait]
impl Transform for RedisPrefixRewrite {
    fn get_name(&self) -> &'static str {
        NAME
    }

    async fn transform<'shorter, 'longer: 'shorter>(
        &mut self,
        chain_state: &'shorter mut ChainState<'longer>,
    ) -> Result<Messages> {
        self.request_commands.clear();

        // 1. Rewrite keys in requests
        for message in chain_state.requests.iter_mut() {
            let mut cmd_name = String::new();
            if let Some(Frame::Valkey(ValkeyFrame::Array(args))) = message.frame() {
                if !args.is_empty() {
                    if let ValkeyFrame::BulkString(bytes) = &args[0] {
                        if let Ok(s) = std::str::from_utf8(bytes) {
                            cmd_name = s.to_ascii_uppercase();
                        }
                    }
                }
            }

            if !cmd_name.is_empty() {
                if let Some(Frame::Valkey(ValkeyFrame::Array(args))) = message.frame() {
                    rewrite_request_keys(&cmd_name, args, &self.translations);
                }
                message.invalidate_cache();
            }

            self.request_commands.push(cmd_name);
        }

        // 2. Call next transform down the chain
        let mut responses = chain_state.call_next_transform().await?;

        // 3. Rewrite keys in responses
        for (i, response) in responses.iter_mut().enumerate() {
            let corresponding_cmd = self.request_commands.get(i).cloned().unwrap_or_default();
            if let Some(Frame::Valkey(frame)) = response.frame() {
                rewrite_response_keys(&corresponding_cmd, frame, &self.translations);
                response.invalidate_cache();
            }
        }

        Ok(responses)
    }
}

fn rewrite_request_keys(command: &str, args: &mut [ValkeyFrame], translations: &[Translation]) {
    match command {
        "GET" | "EXPIRE" | "TTL" | "SET" | "SETEX" => {
            if args.len() > 1 {
                rewrite_key_value(&mut args[1], translations);
            }
        }
        "DEL" | "EXISTS" | "MGET" => {
            for key_arg in args.iter_mut().skip(1) {
                rewrite_key_value(key_arg, translations);
            }
        }
        "MSET" => {
            let mut i = 1;
            while i < args.len() {
                rewrite_key_value(&mut args[i], translations);
                i += 2;
            }
        }
        "KEYS" => {
            if args.len() > 1 {
                rewrite_key_value(&mut args[1], translations);
            }
        }
        "SCAN" => {
            let mut i = 1;
            while i < args.len() - 1 {
                if let ValkeyFrame::BulkString(bytes) = &args[i] {
                    if let Ok(arg_str) = std::str::from_utf8(bytes) {
                        if arg_str.to_ascii_uppercase() == "MATCH" {
                            rewrite_key_value(&mut args[i + 1], translations);
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

fn rewrite_key_value(value: &mut ValkeyFrame, translations: &[Translation]) {
    if let ValkeyFrame::BulkString(bytes) = value {
        if let Ok(key_str) = std::str::from_utf8(bytes) {
            for rule in translations {
                if key_str.starts_with(&rule.from) {
                    let rewritten = key_str.replace(&rule.from, &rule.to);
                    *bytes = bytes::Bytes::from(rewritten);
                    break;
                }
            }
        }
    }
}

fn rewrite_response_keys(command: &str, value: &mut ValkeyFrame, translations: &[Translation]) {
    match value {
        ValkeyFrame::BulkString(bytes) => {
            if command == "KEYS" {
                revert_key_value(bytes, translations);
            }
        }
        ValkeyFrame::Array(items) => {
            if command == "KEYS" {
                for item in items {
                    if let ValkeyFrame::BulkString(bytes) = item {
                        revert_key_value(bytes, translations);
                    }
                }
            } else if command == "SCAN" {
                if items.len() > 1 {
                    if let ValkeyFrame::Array(keys_array) = &mut items[1] {
                        for item in keys_array {
                            if let ValkeyFrame::BulkString(bytes) = item {
                                revert_key_value(bytes, translations);
                            }
                        }
                    }
                }
            }
        }
        ValkeyFrame::SimpleString(status_bytes) => {
            if let Ok(status_str) = std::str::from_utf8(status_bytes) {
                for rule in translations {
                    if status_str.contains(&rule.to) {
                        let reverted = status_str.replace(&rule.to, &rule.from);
                        *status_bytes = bytes::Bytes::from(reverted);
                    }
                }
            }
        }
        ValkeyFrame::Error(err_bytes) => {
            if let Ok(err_str) = std::str::from_utf8(err_bytes) {
                for rule in translations {
                    if err_str.contains(&rule.to) {
                        let reverted = err_str.replace(&rule.to, &rule.from);
                        *err_bytes = bytes::Bytes::from(reverted);
                    }
                }
            }
        }
        _ => {}
    }
}

fn revert_key_value(bytes: &mut bytes::Bytes, translations: &[Translation]) {
    if let Ok(key_str) = std::str::from_utf8(bytes) {
        for rule in translations {
            if key_str.starts_with(&rule.to) {
                let reverted = key_str.replace(&rule.to, &rule.from);
                *bytes = bytes::Bytes::from(reverted);
                break;
            }
        }
    }
}
