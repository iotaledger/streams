use core::{convert::TryFrom, cell::RefCell};
use wasm_bindgen::prelude::*;
use iota_streams::{
    app::transport::{
        tangle::client::{SendTrytesOptions as ApiSendTrytesOptions, Client },
    },
    app_channels::{
        api::tangle::{
            Address as ApiAddress,
            UnwrappedMessage,
            MessageContent,
        },
    },
    core::prelude::{ String, ToString, Rc, },
    ddml::types::hex,
};

use js_sys::Array;

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

    #[wasm_bindgen]
    pub fn clone(&self) -> Self {
        self.clone()
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

    pub fn eq(&self, addr: Address) -> bool {
        self.msg_id.eq(&addr.msg_id) && self.addr_id.eq(&addr.addr_id)
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

pub fn get_message_contents(msgs: Vec<UnwrappedMessage>) -> Vec<UserResponse> {
    let mut payloads = Vec::new();
    for msg in msgs {
        match msg.body {
            MessageContent::SignedPacket { pk, public_payload: p, masked_payload: m } => {
                payloads.push(UserResponse::new(
                    Address::from_string(msg.link.to_string()),
                    None,
                    Some(Message::new(
                        Some(hex::encode(pk.to_bytes())),
                        p.0,
                        m.0
                    )
                    )
                ))
            },
            MessageContent::TaggedPacket { public_payload: p, masked_payload: m } => {
                payloads.push(UserResponse::new(
                    Address::from_string(msg.link.to_string()),
                    None,
                    Some(Message::new(None, p.0, m.0))
                ))
            },
            MessageContent::Sequence => (),
            _ => payloads.push(UserResponse::new(
                Address::from_string(msg.link.to_string()), None, None)
            )
        };
    };
    payloads
}


#[wasm_bindgen]
pub struct UserResponse {
    link: Address,
    seq_link: Option<Address>,
    message: Option<Message>
}

#[wasm_bindgen]
pub struct NextMsgId {
    pk: String,
    msgid: Address
}


#[wasm_bindgen]
pub struct Message {
    pk: Option<String>,
    public_payload: Vec<u8>,
    masked_payload: Vec<u8>,
}

#[wasm_bindgen]
pub struct PskIds {
    ids: Vec<String>
}


#[wasm_bindgen]
pub struct PublicKeys {
    pks: Vec<String>
}

#[wasm_bindgen]
impl PskIds {
    pub fn new() -> Self {
        PskIds { ids: Vec::new() }
    }

    pub fn add(&mut self, id: String) {
        self.ids.push(id);
    }

    pub fn get_ids(&self) -> Array {
        self.ids.iter().map(JsValue::from).collect()
    }
}

#[wasm_bindgen]
impl PublicKeys {
    pub fn new() -> Self {
        PublicKeys { pks: Vec::new() }
    }

    pub fn add(&mut self, id: String) {
        self.pks.push(id);
    }

    pub fn get_pks(&self) -> Array {
        self.pks.iter().map(JsValue::from).collect()
    }
}


#[wasm_bindgen]
impl Message {
    pub fn default() -> Message {
        Self::new(None, Vec::new(), Vec::new())
    }

    pub fn new(pk: Option<String>, public_payload: Vec<u8>, masked_payload: Vec<u8>) -> Message {
        Message { pk, public_payload, masked_payload }
    }

    pub fn get_pk(&self) -> String {
        self.pk.clone().unwrap_or(String::new())
    }

    pub fn get_public_payload(&self) -> Array {
        self.public_payload.clone().into_iter().map(JsValue::from).collect()
    }

    pub fn get_masked_payload(&self) -> Array {
        self.masked_payload.clone().into_iter().map(JsValue::from).collect()
    }

}

#[wasm_bindgen]
impl NextMsgId {
    pub fn new(pk: String, msgid: Address) -> Self {
        NextMsgId { pk, msgid }
    }

    pub fn get_pk(&self) -> String {
        self.pk.clone()
    }

    pub fn get_link(&self) -> Address {
        self.msgid.copy()
    }
}

#[wasm_bindgen]
impl UserResponse {
    pub fn new(link: Address, seq_link: Option<Address>, message: Option<Message>) -> Self {
        UserResponse { link, seq_link, message }
    }

    pub fn from_strings(
        link: String,
        seq_link: Option<String>,
        message: Option<Message>
    ) -> Self {
        let seq;
        if let Some(seq_link) = seq_link {
            seq = Some(Address::from_string(seq_link));
        } else {
            seq = None;
        }

        UserResponse {
            link: Address::from_string(link.to_string()),
            seq_link: seq,
            message
        }
    }

    pub fn copy(&self) -> Self {
        let mut seq = None;
        if !self.get_seq_link().eq(Address::new()) {
            seq = Some(self.get_seq_link());
        }
        UserResponse::new(self.get_link(), seq, None)
    }

    pub fn get_link(&self) -> Address {
        let mut link = Address::new();
        link.set_addr_id(self.link.addr_id());
        link.set_msg_id(self.link.msg_id());
        link
    }

    pub fn get_seq_link(&self) -> Address {
        if self.seq_link.is_some() {
            let seq_link = self.seq_link.as_ref().unwrap();
            let mut link = Address::new();
            link.set_addr_id(seq_link.addr_id());
            link.set_msg_id(seq_link.msg_id());
            link
        } else {
            Address::new()
        }
    }

    pub fn get_message(&mut self) -> Message {
        if self.message.is_some() {
            let message = self.message.as_ref().unwrap();
            Message {
                pk: message.pk.clone(),
                public_payload: message.public_payload.clone(),
                masked_payload: message.masked_payload.clone()
            }
        } else {
            Message::default()
        }
    }
}
