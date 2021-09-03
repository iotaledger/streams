// Copyright 2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::unnecessary_wraps)]
use wasm_bindgen::prelude::*;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use iota_streams::{
    app::transport::tangle::client::iota_client::{ClientBuilder as ClientBuilderRust},
};

use js_sys::JsString;

use crate::{
    user::userw::{
        Client, new_with_client
    },
    types::{
        SendOptions, Api
    },
};

#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone)]
pub struct NodeAuthOptions {
    jwt: Option<String>,
    basic_auth_name: Option<String>,
    basic_auth_password: Option<String>,
}

#[wasm_bindgen]
impl NodeAuthOptions {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self { jwt: None, basic_auth_name: None, basic_auth_password: None }
    }

    #[wasm_bindgen(setter)]
    pub fn set_jwt(&mut self, jwt: String) {
        self.jwt = Some(jwt)
    }

    #[wasm_bindgen(setter)]
    pub fn set_auth_name(&mut self, name: String) {
        self.basic_auth_name = Some(name)
    }

    #[wasm_bindgen(setter)]
    pub fn set_auth_password(&mut self, password: String) {
        self.basic_auth_password = Some(password)
    }

    #[wasm_bindgen]
    #[allow(clippy::should_implement_trait)]
    pub fn clone(&self) -> Self {
        NodeAuthOptions {
            jwt: self.jwt.clone(),
            basic_auth_name: self.basic_auth_name.clone(),
            basic_auth_password: self.basic_auth_password.clone(),
        }
    }
}

#[wasm_bindgen]
pub struct ClientBuilder(ClientBuilderRust);

/// Builder to construct client instance with sensible default values
#[wasm_bindgen]
impl ClientBuilder {
    /// Creates an IOTA client builder.
    #[wasm_bindgen(constructor)]
    pub fn default() -> ClientBuilder {
        Self(ClientBuilderRust::default())
    }

    /// Adds an IOTA node by its URL.
    #[wasm_bindgen(catch)]
    pub fn node(mut self, node: &str) -> ClientBuilder {
        self.0 = self.0
            .with_node(node)
            .unwrap();
        self
    }

    /// Adds an IOTA node by its URL to be used as primary node, with optional jwt and or basic authentication
    #[wasm_bindgen(catch, js_name = "primaryNode")]
    pub fn with_primary_node(mut self, node: &str, options: NodeAuthOptions) -> ClientBuilder {
        let basic_auth: Option<(&str, &str)> = match &options {
            NodeAuthOptions {
                basic_auth_name: Some(u),
                basic_auth_password: Some(p),
                ..
            } => Some((u, p)),
            _ => None,
        };
        self.0 = self.0
            .with_primary_node(node, options.jwt.as_ref().map(|s| s.into()), basic_auth)
            .unwrap();
        self
    }

    /// Adds an IOTA node by its URL to be used as primary PoW node (for remote PoW), with optional jwt and or basic
    /// authentication
    #[wasm_bindgen(catch, js_name = "primaryPowNode")]
    pub fn with_primary_pow_node(mut self, node: &str, options: NodeAuthOptions) -> ClientBuilder {
        let basic_auth: Option<(&str, &str)> = match &options {
            NodeAuthOptions {
                basic_auth_name: Some(u),
                basic_auth_password: Some(p),
                ..
            } => Some((u, p)),
            _ => None,
        };
        self.0 = self.0
            .with_primary_pow_node(node, options.jwt.as_ref().map(|s| s.into()), basic_auth)
            .unwrap();
        self
    }

    /// Adds a permanode by its URL, with optional jwt and or basic authentication
    #[wasm_bindgen(catch, js_name = "permanode")]
    pub fn with_permanode(mut self, node: &str, options: NodeAuthOptions) -> ClientBuilder {
        let basic_auth: Option<(&str, &str)> = match &options {
            NodeAuthOptions {
                basic_auth_name: Some(u),
                basic_auth_password: Some(p),
                ..
            } => Some((u, p)),
            _ => None,
        };
        self.0 = self.0
            .with_permanode(node, options.jwt.as_ref().map(|s| s.into()), basic_auth)
            .unwrap();
        self
    }

    /// Adds an IOTA node by its URL with optional jwt and or basic authentication
    #[wasm_bindgen(catch, js_name = "nodeAuth")]
    pub fn with_node_auth(mut self, node: &str, options: NodeAuthOptions) -> ClientBuilder {
        let basic_auth: Option<(&str, &str)> = match &options {
            NodeAuthOptions {
                basic_auth_name: Some(u),
                basic_auth_password: Some(p),
                ..
            } => Some((u, p)),
            _ => None,
        };
        self.0 = self.0
            .with_node_auth(node, options.jwt.as_ref().map(|s| s.into()), basic_auth)
            .unwrap();

        self
    }

    /// Adds a list of IOTA nodes by their URLs.
    #[wasm_bindgen(catch, js_name = "nodes")]
    pub fn with_nodes(mut self, urls: Vec<JsString>) -> ClientBuilder {
        let url_str: Vec<String> = urls.into_iter().map(|s| {
            s.into()
        }).collect();
        self.0 = self.0
            .with_nodes(&url_str.iter().map(|s| {
                s as &str
            }).collect::<Vec<&str>>())
            .unwrap();
        self
    }

    /// Get node list from the node_pool_urls
    #[wasm_bindgen(catch, js_name = "nodePoolUrls")]
    pub async fn with_node_pool_urls(mut self, urls: Vec<JsString>) -> ClientBuilder {
        self.0 = self.0
            .with_node_pool_urls(&urls.into_iter().map(|s| s.into()).collect::<Vec<String>>())
            .await
            .unwrap();
        self
    }

    /// Set if quroum should be used or not
    #[wasm_bindgen(catch, js_name = "quorum")]
    pub fn with_quorum(mut self, quorum_on: bool) -> ClientBuilder {
        self.0 = self.0
            .with_quorum(quorum_on);
        self
    }

    /// Set amount of nodes which should be used for quorum
    #[wasm_bindgen(catch, js_name = "quorumSize")]
    pub fn with_quorum_size(mut self, quorum_size: usize) -> ClientBuilder {
        self.0 = self.0
            .with_quorum_size(quorum_size);
        self
    }

    /// Set quorum_threshold
    #[wasm_bindgen(catch, js_name = "quorumThreshold")]
    pub fn with_quorum_threshold(mut self, quorum_threshold: usize) -> ClientBuilder {
        self.0 = self.0
            .with_quorum_threshold(quorum_threshold);
        self
    }

    /// Selects the type of network to get default nodes for it, only "testnet" is supported at the moment.
    /// Nodes that don't belong to this network are ignored. Default nodes are only used when no other nodes are
    /// provided.
    #[wasm_bindgen(catch, js_name = "network")]
    pub fn with_network(mut self, network: &str) -> ClientBuilder {
        self.0 = self.0
            .with_network(network);
        self
    }

    /// Set the node sync interval in seconds
    #[wasm_bindgen(catch, js_name = "nodeSyncInterval")]
    pub fn with_node_sync_interval(mut self, node_sync_interval_sec: u64) -> ClientBuilder {
        self.0 = self.0
            .with_node_sync_interval(Duration::from_secs(node_sync_interval_sec));
        self
    }

    /// Disables the node syncing process.
    /// Every node will be considered healthy and ready to use.
    #[wasm_bindgen(catch, js_name = "disableNodeSync")]
    pub fn with_node_sync_disabled(mut self) -> ClientBuilder {
        self.0 = self.0
            .with_node_sync_disabled();
        self
    }

    /// Allows creating the client without nodes for offline address generation or signing
    #[wasm_bindgen(catch, js_name = "offlineMode")]
    pub fn with_offline_mode(mut self) -> ClientBuilder {
        self.0 = self.0
            .with_offline_mode();
        self
    }

    /// Sets the default request timeout in seconds.
    #[wasm_bindgen(catch, js_name = "requestTimeout")]
    pub fn with_request_timeout(mut self, timeout_sec: u64) -> ClientBuilder {
        self.0 = self.0
            .with_request_timeout(Duration::from_secs(timeout_sec));
        self
    }

    /// Sets the request timeout in seconds for a specific API usage.
    #[wasm_bindgen(catch, js_name = "apiTimeout")]
    pub fn with_api_timeout(mut self, api: Api, timeout_sec: u64) -> ClientBuilder {
        self.0 = self.0
            .with_api_timeout(api.into(), Duration::from_secs(timeout_sec));
        self
    }

    /// Sets whether the PoW should be done locally or remotely.
    #[wasm_bindgen(catch, js_name = "localPow")]
    pub fn with_local_pow(mut self, local: bool) -> ClientBuilder {
        self.0 = self.0
            .with_local_pow(local);
        self
    }

    /// Sets after how many seconds new tips will be requested during PoW
    #[wasm_bindgen(catch, js_name = "tipsInterval")]
    pub fn with_tips_interval(mut self, tips_interval: u64) -> ClientBuilder {
        self.0 = self.0
            .with_tips_interval(tips_interval);
        self
    }

    /// Build the Streams Client instance.
    #[wasm_bindgen(catch)]
    pub async fn finish(self, options: SendOptions) -> Client {
        new_with_client(self.0
            .finish().await
            .unwrap(), options)
    }
}