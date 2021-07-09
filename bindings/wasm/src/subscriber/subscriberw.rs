use core::convert::TryInto as _;
use js_sys::Array;
use wasm_bindgen::prelude::*;

use crate::{
    types::*,
    user::userw::*,
};

use core::cell::RefCell;
use iota_streams::{
    app::transport::{
        tangle::{
            client::Client as ApiClient,
            PAYLOAD_BYTES,
        },
        TransportOptions,
    },
    app_channels::api::{
        psk_from_seed,
        pskid_from_psk,
        tangle::{
            Address as ApiAddress,
            Subscriber as ApiSubscriber,
        },
    },
    core::{
        prelude::{
            Rc,
            String,
        },
        psk::pskid_to_hex_string,
    },
    ddml::types::*,
};

#[wasm_bindgen]
pub struct Subscriber {
    subscriber: Rc<RefCell<ApiSubscriber<ClientWrap>>>,
}

#[wasm_bindgen]
impl Subscriber {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: String, options: SendOptions) -> Subscriber {
        let mut client = ApiClient::new_from_url(&options.url());
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));

        let subscriber = Rc::new(RefCell::new(ApiSubscriber::new(
            &seed,
            "utf-8",
            PAYLOAD_BYTES,
            transport,
        )));
        Subscriber { subscriber }
    }

    pub fn from_client(client: Client, seed: String) -> Subscriber {
        let subscriber = Rc::new(RefCell::new(ApiSubscriber::new(
            &seed,
            "utf-8",
            PAYLOAD_BYTES,
            client.to_inner(),
        )));
        Subscriber { subscriber }
    }

    #[wasm_bindgen(catch)]
    pub fn import(client: Client, bytes: Vec<u8>, password: &str) -> Result<Subscriber> {
        ApiSubscriber::import(&bytes, password, client.to_inner()).map_or_else(
            |err| Err(JsValue::from_str(&err.to_string())),
            |v| {
                Ok(Subscriber {
                    subscriber: Rc::new(RefCell::new(v)),
                })
            },
        )
    }

    #[wasm_bindgen(catch)]
    pub fn export(&self, password: &str) -> Result<Vec<u8>> {
        self.subscriber
            .borrow_mut()
            .export(password)
            .map_or_else(|err| Err(JsValue::from_str(&err.to_string())), |v| Ok(v))
    }

    pub fn clone(&self) -> Subscriber {
        Subscriber {
            subscriber: self.subscriber.clone(),
        }
    }

    #[wasm_bindgen(catch)]
    pub fn channel_address(&self) -> Result<String> {
        to_result(
            self.subscriber
                .borrow_mut()
                .channel_address()
                .map(|addr| addr.to_string())
                .ok_or("channel not subscribed"),
        )
    }

    #[wasm_bindgen(catch)]
    pub fn get_client(&self) -> Client {
        Client(self.subscriber.borrow_mut().get_transport().clone())
    }

    #[wasm_bindgen(catch)]
    pub fn is_multi_branching(&self) -> Result<bool> {
        Ok(self.subscriber.borrow_mut().is_multi_branching())
    }

    #[wasm_bindgen(catch)]
    pub fn store_psk(&self, psk_seed_str: String) -> String {
        let psk = psk_from_seed(psk_seed_str.as_bytes());
        let pskid = pskid_from_psk(&psk);
        let pskid_str = pskid_to_hex_string(&pskid);
        self.subscriber.borrow_mut().store_psk(pskid, psk);
        pskid_str
    }

    #[wasm_bindgen(catch)]
    pub fn get_public_key(&self) -> Result<String> {
        Ok(public_key_to_string(self.subscriber.borrow_mut().get_pk()))
    }

    #[wasm_bindgen(catch)]
    pub fn is_registered(&self) -> Result<bool> {
        Ok(self.subscriber.borrow_mut().is_registered())
    }

    #[wasm_bindgen(catch)]
    pub fn unregister(&self) -> Result<()> {
        Ok(self.subscriber.borrow_mut().unregister())
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_announcement(self, link: Address) -> Result<()> {
        self.subscriber
            .borrow_mut()
            .receive_announcement(&link.try_into().map_or_else(|_err| ApiAddress::default(), |addr| addr))
            .await
            .map_or_else(|err| Err(JsValue::from_str(&err.to_string())), |_| Ok(()))
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_keyload(self, link: Address) -> Result<bool> {
        self.subscriber
            .borrow_mut()
            .receive_keyload(&link.try_into().map_or_else(|_err| ApiAddress::default(), |addr| addr))
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |processed| Ok(processed),
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_tagged_packet(self, link: Address) -> Result<UserResponse> {
        self.subscriber
            .borrow_mut()
            .receive_tagged_packet(
                &link
                    .copy()
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr| addr),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(pub_bytes, masked_bytes)| {
                    Ok(UserResponse::new(
                        link,
                        None,
                        Some(Message::new(None, pub_bytes.0, masked_bytes.0)),
                    ))
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_signed_packet(self, link: Address) -> Result<UserResponse> {
        self.subscriber
            .borrow_mut()
            .receive_signed_packet(
                &link
                    .copy()
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr| addr),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(pk, pub_bytes, masked_bytes)| {
                    Ok(UserResponse::new(
                        link,
                        None,
                        Some(Message::new(
                            Some(public_key_to_string(&pk)),
                            pub_bytes.0,
                            masked_bytes.0,
                        )),
                    ))
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_sequence(self, link: Address) -> Result<Address> {
        self.subscriber
            .borrow_mut()
            .receive_sequence(&link.try_into().map_or_else(|_err| ApiAddress::default(), |addr| addr))
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |address| Ok(Address::from_string(address.to_string())),
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn receive_msg(self, link: Address) -> Result<UserResponse> {
        self.subscriber
            .borrow_mut()
            .receive_msg(&link.try_into().map_or_else(|_err| ApiAddress::default(), |addr| addr))
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |msg| {
                    let mut msgs = Vec::new();
                    msgs.push(msg);
                    let responses = get_message_contents(msgs);
                    Ok(responses[0].copy())
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_subscribe(self, link: Address) -> Result<UserResponse> {
        self.subscriber
            .borrow_mut()
            .send_subscribe(
                &link
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr: ApiAddress| addr),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |link| Ok(UserResponse::new(Address::from_string(link.to_string()), None, None)),
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_tagged_packet(
        self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>,
    ) -> Result<UserResponse> {
        self.subscriber
            .borrow_mut()
            .send_tagged_packet(
                &link
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr: ApiAddress| addr),
                &Bytes(public_payload),
                &Bytes(masked_payload),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(
                            link.to_string(),
                            Some(seq_link.to_string()),
                            None,
                        ))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_signed_packet(
        self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>,
    ) -> Result<UserResponse> {
        self.subscriber
            .borrow_mut()
            .send_signed_packet(
                &link
                    .try_into()
                    .map_or_else(|_err| ApiAddress::default(), |addr: ApiAddress| addr),
                &Bytes(public_payload),
                &Bytes(masked_payload),
            )
            .await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |(link, seq_link)| {
                    if let Some(seq_link) = seq_link {
                        Ok(UserResponse::from_strings(
                            link.to_string(),
                            Some(seq_link.to_string()),
                            None,
                        ))
                    } else {
                        Ok(UserResponse::from_strings(link.to_string(), None, None))
                    }
                },
            )
    }

    #[wasm_bindgen(catch)]
    pub async fn sync_state(self) -> Result<()> {
        loop {
            let msgs = self.subscriber.borrow_mut().fetch_next_msgs().await;
            if msgs.is_empty() {
                break;
            }
        }
        Ok(())
    }

    #[wasm_bindgen(catch)]
    pub async fn fetch_next_msgs(self) -> Result<Array> {
        let msgs = self.subscriber.borrow_mut().fetch_next_msgs().await;
        let payloads = get_message_contents(msgs);
        Ok(payloads.into_iter().map(JsValue::from).collect())
    }
}
