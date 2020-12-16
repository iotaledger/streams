use core::convert::TryInto as _;
use wasm_bindgen::prelude::*;

use crate::types::*;

use iota_streams::{
  app::transport::tangle::PAYLOAD_BYTES,
  app_channels::{
      api::tangle::{
          Address as ApiAddress,
          Subscriber as ApiSubscriber,
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
  core::prelude::{ String,  },
};
use crate::log;

#[wasm_bindgen]
pub struct Subscriber {
  subscriber: Rc<RefCell<ApiSubscriber<ClientWrap>>>,
}

#[wasm_bindgen]
impl Subscriber {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, seed: String, options: SendTrytesOptions) -> Subscriber {
        let mut client = Client::new_from_url(&node);
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));

        let subscriber = Rc::new(RefCell::new(
            ApiSubscriber::new(&seed, "utf-8", PAYLOAD_BYTES, transport)));
        Subscriber { subscriber }
    }

    pub fn clone(&self) -> Subscriber {
        Subscriber { subscriber: self.subscriber.clone() }
    }

    #[wasm_bindgen(catch)]
    pub fn channel_address(&self) -> Result<String> {
        to_result(self.subscriber.borrow_mut()
                  .channel_address()
                  .map(|addr| addr.to_string())
                  .ok_or("channel not subscribed")
        )
    }


    #[wasm_bindgen(catch)]
    pub async fn receive_announcement(self, link: Address) -> Result<()> {
        self.subscriber.borrow_mut().receive_announcement(&link.try_into().map_or_else(
                |_err| ApiAddress::default(),
                |addr| addr
            )).await
            .map_or_else(
            |err| Err(JsValue::from_str(&err.to_string())),
            |_| Ok(())
        )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_subscribe(self, link: Address) -> Result<UserResponse> {
        self.subscriber.borrow_mut().send_subscribe(&link.try_into().map_or_else(
                |_err| ApiAddress::default(),
                |addr: ApiAddress| addr
            )).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |link| Ok(UserResponse::new(
                    Address::from_string(link.to_string()),
                    None,
                    None
                ))
            )

    }

    #[wasm_bindgen(catch)]
    pub async fn send_tagged_packet(
        self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>
    ) -> Result<UserResponse> {
        self.subscriber.borrow_mut().send_tagged_packet(
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
        self.subscriber.borrow_mut().send_signed_packet(
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
    pub async fn sync_state(self) -> Result<()> {
        loop {
            let msgs = self.subscriber.borrow_mut().fetch_next_msgs().await;
            if msgs.is_empty() {
                break;
            }
        }
        Ok(())
    }



}
