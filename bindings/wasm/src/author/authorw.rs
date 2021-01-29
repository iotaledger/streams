use core::convert::TryInto as _;
use wasm_bindgen::prelude::*;
//use wasm_bindgen_futures::*;

use js_sys::Array;
use crate::types::PskIds as PskIdsW;
use crate::types::PublicKeys as PublicKeysW;
use crate::types::*;

/// Streams imports
use iota_streams::{
    app::transport::{
        TransportOptions,
        tangle::{
            client::Client,
            PAYLOAD_BYTES
        }
    },
    app_channels::{
        api::tangle::{
            Author as ApiAuthor,
            Address as ApiAddress,
            PublicKey,
        },
    },
    core::{
        prelude::{Rc, String, ToString},
        psk::{PskIds, PSKID_SIZE}
    },
    ddml::types::*,
};
use core::cell::RefCell;


#[wasm_bindgen]
pub struct Author {
    author: Rc<RefCell<ApiAuthor<ClientWrap>>>,
}

#[wasm_bindgen]
impl Author {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, seed: String, options: SendOptions, multi_branching: bool) -> Author {
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

    #[wasm_bindgen(catch)]
    pub fn channel_address(&self) -> Result<String> {
        to_result(self.author.borrow_mut().channel_address()
                  .map(|addr| addr.to_string())
                  .ok_or("channel not created")
        )
    }

    #[wasm_bindgen(catch)]
    pub fn is_multi_branching(&self) -> Result<bool> {
        Ok(self.author.borrow_mut().is_multi_branching())
    }

    #[wasm_bindgen(catch)]
    pub fn get_public_key(&self) -> Result<String> {
        Ok(hex::encode(self.author.borrow_mut().get_pk().to_bytes()))
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
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(link.to_string(), Some(seq_link.to_string()), None))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
                }
            )

    }


    #[wasm_bindgen(catch)]
    pub async fn send_keyload(
        self,
        link: Address,
        psk_ids: PskIdsW,
        sig_pks: PublicKeysW
    ) -> Result<UserResponse> {
        let mut preshared = PskIds::new();

        let ids = psk_ids.get_ids().entries();

        for id in ids {
            if let Some(id_str) = id.unwrap().as_string() {
                if id_str.as_bytes().len() != PSKID_SIZE {
                    return Err(JsValue::from_str("PskId is wrong size"))
                }
                let gen_arr = GenericArray::clone_from_slice(id_str.as_bytes());
                preshared.push(gen_arr);
            }
        }


        let mut pks = Vec::new();

        let pk_list = sig_pks.get_pks().entries();

        for pk in pk_list {
            if let Some(pk_str) = pk.unwrap().as_string() {
                pks.push(PublicKey::from_bytes(pk_str.as_bytes())
                    .unwrap_or_default());
            }
        }

        self.author.borrow_mut().send_keyload(
            &link.try_into().map_or_else(
                |_err| ApiAddress::default(),
                |addr: ApiAddress| addr
                ), &preshared,
            &pks
        ).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(link.to_string(), Some(seq_link.to_string()), None))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
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
            ), &Bytes(public_payload.clone()),
            &Bytes(masked_payload.clone())
        ).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(link.to_string(), Some(seq_link.to_string()), None))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
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
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(link.to_string(), Some(seq_link.to_string()), None))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
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
    pub async fn receive_tagged_packet(self, link: Address) -> Result<UserResponse> {
        self.author.borrow_mut().receive_tagged_packet(&link.copy().try_into().map_or_else(
            |_err| ApiAddress::default(),
            |addr| addr
        )).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(pub_bytes, masked_bytes)| {
                    Ok(UserResponse::new(
                        link,
                        None,
                        Some(
                            Message::new(
                                None,
                                pub_bytes.0,
                                masked_bytes.0
                            )
                        )
                    ))
                }
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_signed_packet(self, link: Address) -> Result<UserResponse> {
        self.author.borrow_mut().receive_signed_packet(&link.copy().try_into().map_or_else(
            |_err| ApiAddress::default(),
            |addr| addr
        )).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(pk, pub_bytes, masked_bytes)| {
                    Ok(UserResponse::new(
                        link,
                        None,
                        Some(
                            Message::new(
                                Some(hex::encode(pk.as_bytes())),
                                pub_bytes.0,
                                masked_bytes.0
                            )
                        )
                    ))
                }
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_sequence(self, link: Address) -> Result<Address> {
        self.author.borrow_mut().receive_sequence(&link.try_into().map_or_else(
            |_err| ApiAddress::default(),
            |addr| addr
        )).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |address| {
                    Ok(Address::from_string(address.to_string()))
                }
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_msg(self, link: Address) -> Result<UserResponse> {
        self.author.borrow_mut().receive_msg(&link.try_into().map_or_else(
            |_err| ApiAddress::default(),
            |addr| addr
        )).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |msg| {
                    let mut msgs = Vec::new();
                    msgs.push(msg);
                    let responses = get_message_contents(msgs);
                    Ok(responses[0].copy())
                }
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
        let msgs = self.author.borrow_mut().fetch_next_msgs().await;
        let payloads = get_message_contents(msgs);
        Ok(payloads.into_iter().map(JsValue::from).collect())
    }

    #[wasm_bindgen(catch)]
    pub async fn gen_next_msg_ids(self) -> Result<Array> {
        let branching = self.author.borrow_mut().is_multi_branching();
        let mut ids = Vec::new();
        for (pk, cursor) in self.author.borrow_mut().gen_next_msg_ids(branching).iter() {
            ids.push(NextMsgId::new(hex::encode(pk.as_bytes()),
                                    Address::from_string(cursor.link.to_string())
            ));
        }
        Ok(ids.into_iter().map(JsValue::from).collect())
    }
}
