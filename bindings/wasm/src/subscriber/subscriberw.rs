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

#[wasm_bindgen]
pub struct Subscriber {
  subscriber: ApiSubscriber<ClientWrap>,
}

#[wasm_bindgen]
pub struct SubscriberResponse {
    subscriber: Subscriber,
    link: Address,
    seq_link: Option<Address>,
}

#[wasm_bindgen]
impl SubscriberResponse {
    fn new(subscriber: ApiSubscriber<ClientWrap>, link: Address, seq_link: Option<Address>) -> Self {
        SubscriberResponse { subscriber: Subscriber { subscriber }, link, seq_link }
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

    pub fn to_sub(self) -> Subscriber {
        self.subscriber
    }
}


#[wasm_bindgen]
impl Subscriber {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, seed: String, options: SendTrytesOptions) -> Subscriber {
        let mut client = Client::new_from_url(&node);
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));

        let subscriber = ApiSubscriber::new(&seed, "utf-8", PAYLOAD_BYTES, transport);
        Subscriber { subscriber }
    }

    pub fn channel_address(&self) -> Result<String> {
        let sub = &self.subscriber;
        to_result(sub
                  .channel_address()
                  .map(|addr| addr.to_string())
                  .ok_or("channel not subscribed")
        )
    }


    #[wasm_bindgen(catch)]
    pub async fn receive_announcement(mut self, link: Address) -> Result<Subscriber> {
        self.subscriber.receive_announcement(&link.try_into().map_or_else(
                |_err| ApiAddress::default(),
                |addr| addr
            )).await
            .map_or_else(
            |err| Err(JsValue::from_str(&err.to_string())),
            |_| Ok(Subscriber { subscriber: self.subscriber })
        )
    }

    #[wasm_bindgen(catch)]
    pub async fn send_subscribe(mut self, link: Address) -> Result<SubscriberResponse> {
        self.subscriber.send_subscribe(&link.try_into().map_or_else(
                |_err| ApiAddress::default(),
                |addr: ApiAddress| addr
            )).await
            .map_or_else(
                |err| Err(JsValue::from_str(&err.to_string())),
                |link| Ok(SubscriberResponse::new(
                    self.subscriber,
                    Address::from_string(link.to_string()),
                    None,
                ))
            )

    }

    #[wasm_bindgen(catch)]
    pub async fn send_tagged_packet(
        mut self,
        link: Address,
        public_payload: Vec<u8>,
        masked_payload: Vec<u8>
    ) -> Result<SubscriberResponse> {
        self.subscriber.send_tagged_packet(
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

                    Ok(SubscriberResponse::new(
                        self.subscriber,
                        Address::from_string(link.to_string()),
                            seq
                    ))
                }
            )

    }


}
