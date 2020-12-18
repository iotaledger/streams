use core::convert::TryInto as _;
use wasm_bindgen::prelude::*;
//use wasm_bindgen_futures::*;

use js_sys::Array;
use crate::{types::*, log};

/// Streams imports
use iota_streams::{
    app::transport::tangle::PAYLOAD_BYTES,
    app_channels::{
        api::tangle::{
            Author as ApiAuthor,
            Address as ApiAddress,
            MessageContent
        },
    },
    core::prelude::Rc,
    ddml::types::*,
};
use core::cell::RefCell;
use iota_streams::{
    app::transport::{
        TransportOptions,
        tangle::client::{Client, },
    },
    core::prelude::{ String, ToString, },
};
use serde::de::Expected;


#[wasm_bindgen]
pub struct Author {
    author: Rc<RefCell<ApiAuthor<ClientWrap>>>,
}

#[wasm_bindgen]
impl Author {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, seed: String, options: SendTrytesOptions, multi_branching: bool) -> Author {
        let mut client = Client::new_from_url(&node);
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));

        let author = Rc::new(RefCell::new(ApiAuthor::new(
            &seed, "utf-8", PAYLOAD_BYTES, multi_branching, transport)));
        Author { author }
    }

    pub fn clone(&self) -> Author {
        Author { author: self.author.clone() }
    }

    pub fn channel_address(&self) -> Result<String> {
        to_result(self.author.borrow_mut().channel_address()
                  .map(|addr| addr.to_string())
                  .ok_or("channel not created")
        )
    }

    pub fn is_multi_branching(&self) -> Result<bool> {
        Ok(self.author.borrow_mut().is_multi_branching())
    }

    pub fn get_public_key(&self) -> Result<String> {
        Ok(hex::encode(self.author.borrow_mut().get_pk().to_bytes().to_vec()))
    }


    #[wasm_bindgen(catch)]
    pub async fn send_announce(self) -> Result<UserResponse> {
        self.author.borrow_mut().send_announce().await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |addr| Ok(
                    UserResponse::new(
                        Address::from_string(addr.to_string()),
                        None,
                        None
                    )
                )
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_keyload_for_everyone(self, link: Address) -> Result<UserResponse> {
        self.author.borrow_mut().send_keyload_for_everyone(
            &link.try_into().map_or_else(
                |_err| ApiAddress::default(),
                |addr: ApiAddress| addr
            )
        ).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    let seq;
                    if let Some(seq_link) = seq_link {
                        seq = Some(Address::from_string(seq_link.to_string()));
                    } else {
                        seq = None;
                    }

                    Ok(UserResponse::new(
                        Address::from_string(link.to_string()),
                        seq,
                        None
                    ))
                }
            )

    }


    #[wasm_bindgen(catch)]
    pub async fn send_tagged_packet(
        self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>
    ) -> Result<UserResponse> {
        self.author.borrow_mut().send_tagged_packet(
            &link.try_into().map_or_else(
                |_err| ApiAddress::default(),
                |addr: ApiAddress| addr
            ), &Bytes(public_payload),
            &Bytes(masked_payload)
        ).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    let seq;
                    if let Some(seq_link) = seq_link {
                        seq = Some(Address::from_string(seq_link.to_string()));
                    } else {
                        seq = None;
                    }

                    Ok(UserResponse::new(
                        Address::from_string(link.to_string()),
                        seq,
                        None
                    ))
                }
            )

    }

    #[wasm_bindgen(catch)]
    pub async fn send_signed_packet(
        self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>
    ) -> Result<UserResponse> {
        self.author.borrow_mut().send_signed_packet(
            &link.try_into().map_or_else(
                |_err| ApiAddress::default(),
                |addr: ApiAddress| addr
            ), &Bytes(public_payload),
            &Bytes(masked_payload)
        ).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    let seq;
                    if let Some(seq_link) = seq_link {
                        seq = Some(Address::from_string(seq_link.to_string()));
                    } else {
                        seq = None;
                    }

                    Ok(UserResponse::new(
                        Address::from_string(link.to_string()),
                        seq,
                        None
                    ))
                }
            )

    }

    #[wasm_bindgen(catch)]
    pub async fn receive_subscribe(self, link_to: Address) -> Result<()> {
        self.author.borrow_mut().receive_subscribe(&link_to.try_into().map_or_else(
            |_err| ApiAddress::default(),
            |addr| addr
        )).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |_| Ok(())
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn sync_state(self) -> Result<()> {
        loop {
            let msgs = self.author.borrow_mut().fetch_next_msgs().await;
            if msgs.is_empty() {
                break;
            }
        }
        Ok(())
    }

    #[wasm_bindgen(catch)]
    pub async fn fetch_next_msgs(self) -> Result<Array> {
        let mut payloads = Vec::new();
        let msgs = self.author.borrow_mut().fetch_next_msgs().await;

        for msg in msgs {
            let jsMsg = match msg.body {
                MessageContent::SignedPacket {pk: pk, public_payload: p, masked_payload: m} => {
<<<<<<< HEAD
                    payloads.push(UserResponse::new(
                        Address::from_string(msg.link.to_string()),
                        None,
                        Some(Message::new(
                            Some(hex::encode(pk.to_bytes().to_vec())),
                            p.0,
                            m.0
                            )
                        )
                    ))
                },
                MessageContent::TaggedPacket {public_payload: p, masked_payload: m} => {
                    payloads.push(UserResponse::new(
                        Address::from_string(msg.link.to_string()),
                        None,
                        Some(Message::new(None, p.0, m.0))
                    ))
                },
                MessageContent::Sequence => {
                    payloads.push(UserResponse::new(
                        Address::new(),
                        Some(Address::from_string(msg.link.to_string())),
                        None
                    ))
                },
                _ => payloads.push(UserResponse::new(
                    Address::from_string(msg.link.to_string()), None, None)
                    )
            }
        }
        Ok(payloads.into_iter().map(JsValue::from).collect())
    }


    /*
    // Keyload
    // message_links_t
    pub fn send_keyload(&self, link_to: AddressW, psk_ids_t *psk_ids, ke_pks_t ke_pks) -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }

    // Tagged Packets
    // message_links_t
    pub fn send_tagged_packet(&self, message_links_t link_to, uint8_t const *public_payload_ptr, size_t public_payload_size, uint8_t const *masked_payload_ptr, size_t masked_payload_size) -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }

    // packet_payloads_t
    pub fn receive_tagged_packet(&self, address: AddressW) -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }
    // Signed Packets
    // message_links_t
    pub fn send_signed_packet(&self, message_links_t link_to, uint8_t const *public_payload_ptr, size_t public_payload_size, uint8_t const *masked_payload_ptr, size_t masked_payload_size) -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }

    // packet_payloads_t
    pub fn receive_tagged_packet(&self, address: AddressW)  -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }
    // Sequence Message (for multi branch use)
    pub fn receive_sequence(&self,address: AddressW) -> Result<AddressW, JsValue> {
        Ok(seed.to_owned())
    }

    // MsgId generation
    // next_msg_ids_t
    pub fn auth_gen_next_msg_ids(&self) -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }
    // Generic Processing
    // unwrapped_message_t
    pub fn receive_msg(&self, address: AddressW) -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }
    // Fetching/Syncing
    // unwrapped_messages_t

    // unwrapped_messages_t
    pub fn sync_state(&self) -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }
    */
}
