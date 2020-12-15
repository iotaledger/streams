use core::{convert::TryFrom, cell::RefCell};
use wasm_bindgen::prelude::*;
use iota_streams::{
    app::transport::{
        tangle::client::{SendTrytesOptions as ApiSendTrytesOptions, Client },
    },
    app_channels::{
        api::tangle::Address as ApiAddress,
    },
    core::prelude::{ String, ToString, Rc, },
};

use crate::log;

pub type Result<T> = core::result::Result<T, JsValue>;
pub fn to_result<T, E: ToString>(r: core::result::Result<T, E>) -> Result<T> {
    r.map_err(|e| JsValue::from_str(&e.to_string()))
}

#[wasm_bindgen]
pub struct SendTrytesOptions {
    pub depth: u8,
    pub min_weight_magnitude: u8,
    pub local_pow: bool,
    pub threads: usize,
}

impl From<SendTrytesOptions> for ApiSendTrytesOptions {
    fn from(options: SendTrytesOptions) -> Self {
        Self {
            depth: options.depth,
            min_weight_magnitude: options.min_weight_magnitude,
            local_pow: options.local_pow,
            threads: options.threads,
        }
    }
}

#[wasm_bindgen]
impl SendTrytesOptions {
    #[wasm_bindgen(constructor)]
    pub fn new(depth: u8, min_weight_magnitude: u8, local_pow: bool, threads: usize) -> Self {
        Self {
            depth,
            min_weight_magnitude,
            local_pow,
            threads,
        }
   }
}

#[wasm_bindgen]
pub struct Address {
    addr_id: String,
    msg_id: String,
}

#[wasm_bindgen]
impl Address {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Address { addr_id: String::new(), msg_id: String::new() }
    }

    #[wasm_bindgen(getter)]
    pub fn addr_id(&self) -> String {
        self.addr_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_addr_id(&mut self, addr_id: String) {
        self.addr_id = addr_id;
    }

    #[wasm_bindgen(getter)]
    pub fn msg_id(&self) -> String {
        self.msg_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_msg_id(&mut self, msg_id: String) {
        self.msg_id = msg_id;
    }

    #[wasm_bindgen(static_method_of = Address)]
    pub fn from_string(link: String) -> Self {
        let link_vec: Vec<&str> = link
            .strip_prefix("<").unwrap_or(&link)
            .strip_suffix(">").unwrap_or(&link)
            .split(":").collect();

        Address { addr_id: link_vec[0].to_string(), msg_id: link_vec[1].to_string() }
    }

    #[wasm_bindgen]
    pub fn to_string(&self) -> String {
        let mut link = String::new();
        link.push_str(&self.addr_id);
        link.push_str(":");
        link.push_str(&self.msg_id);
        link
    }

    pub fn copy(&self) -> Self {
        Address { addr_id: self.addr_id.clone(), msg_id: self.msg_id.clone() }
    }
}

pub type ClientWrap = Rc<RefCell<Client>>;

impl TryFrom<Address> for ApiAddress {
    type Error = JsValue;
    fn try_from(addr: Address) -> Result<Self> {
        ApiAddress::from_str(&addr.addr_id, &addr.msg_id)
            .map_err(|()| JsValue::from_str("bad address"))
    }
}
