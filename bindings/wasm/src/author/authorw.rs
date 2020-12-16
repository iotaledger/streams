use core::convert::TryInto as _;
use wasm_bindgen::prelude::*;
//use wasm_bindgen_futures::*;

use crate::types::*;

/// Streams imports
use iota_streams::{
    app::transport::tangle::PAYLOAD_BYTES,
    app_channels::{
        api::tangle::{
            Author as ApiAuthor,
            Address as ApiAddress,
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

use wasm_bindgen_futures::*;
use js_sys::Promise;

#[wasm_bindgen]
pub struct Author {
    author: ApiAuthor<ClientWrap>,
}

#[wasm_bindgen]
pub struct AuthorMessage {
    author: Author,
    link: Address,
    msg: Message,
}


#[wasm_bindgen]
impl AuthorMessage {
    fn new(author: ApiAuthor<ClientWrap>, link: Address, msg: Message) -> Self {
        AuthorMessage { author: Author { author }, link, msg }
    }

    pub fn get_link(&self) -> Address {
        let mut link = Address::new();
        link.set_addr_id(self.link.addr_id());
        link.set_msg_id(self.link.msg_id());
        link
    }
}

#[wasm_bindgen]
pub struct AuthorResponse {
    author: Author,
    link: Address,
    seq_link: Option<Address>
}

#[wasm_bindgen]
impl AuthorResponse {
    fn new(author: ApiAuthor<ClientWrap>, link: Address, seq_link: Option<Address>) -> Self {
        AuthorResponse { author: Author { author }, link, seq_link }
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

    pub fn to_auth(self) -> Author {
        self.author
    }
}

#[wasm_bindgen]
impl Author {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, seed: String, options: SendTrytesOptions, multi_branching: bool) -> Author {
        let mut client = Client::new_from_url(&node);
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));

        let author = ApiAuthor::new(
            &seed, "utf-8", PAYLOAD_BYTES, multi_branching, transport);
        Author { author }
    }

    pub fn channel_address(&self) -> Result<String> {
        to_result(self.author.channel_address()
                  .map(|addr| addr.to_string())
                  .ok_or("channel not created")
        )
    }

    pub fn is_multi_branching(&self) -> Result<bool> {
        Ok(self.author.is_multi_branching())
    }

    pub fn get_public_key(&self) -> Result<String> {
        Ok("pk".to_owned())
    }

    #[wasm_bindgen(catch)]
    pub async fn send_announce(mut self) -> Result<AuthorResponse> {
        self.author.send_announce().await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |addr| Ok(
                    AuthorResponse::new(
                        self.author,
                        Address::from_string(addr.to_string()),
                        None
                    )
                )
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_keyload_for_everyone(mut self, link: Address) -> Result<AuthorResponse> {
        self.author.send_keyload_for_everyone(
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

                    Ok(AuthorResponse::new(
                        self.author,
                        Address::from_string(link.to_string()),
                        seq
                    ))
                }
            )

    }


    #[wasm_bindgen(catch)]
    pub async fn send_tagged_packet(
        mut self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>
    ) -> Result<AuthorResponse> {
        self.author.send_tagged_packet(
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

                    Ok(AuthorResponse::new(
                        self.author,
                        Address::from_string(link.to_string()),
                        seq
                    ))
                }
            )

    }

    #[wasm_bindgen(catch)]
    pub async fn send_signed_packet(
        mut self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>
    ) -> Result<AuthorResponse> {
        self.author.send_signed_packet(
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

                    Ok(AuthorResponse::new(
                        self.author,
                        Address::from_string(link.to_string()),
                        seq
                    ))
                }
            )

    }

    #[wasm_bindgen(catch)]
    pub async fn receive_subscribe(mut self, link_to: Address) -> Result<Author> {
        self.author.receive_subscribe(&link_to.try_into().map_or_else(
            |_err| ApiAddress::default(),
            |addr| addr
        )).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |_| Ok(Author { author: self.author })
            )
    }
    
    #[wasm_bindgen(catch)]
    pub async fn fetch_next_msgs(&self) -> Result<AuthorMessage> {
        let unwrapped_msgs_vec = self.author.fetch_next_msgs().await;

        let unwrappedMessage = unwrapped_msgs_vec.get(0).unwrap();

        //MessageContent::TaggedPacket { public_payload: p, masked_payload: m, } => (p, m).into(),
        let body: (_, Bytes, Bytes) = unwrappedMessage.body;
        Ok(AuthorMessage::new(
            self.author,
            Address::from_string(unwrappedMessage.link.to_string()),
            Message::new(body.0.to_string(), body.1.to_string())
        ))
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
