use core::convert::TryInto as _;
use wasm_bindgen::prelude::*;

use crate::types::*;

use iota_streams::{
  app::{
      message::HasLink,
      transport::tangle::PAYLOAD_BYTES,
  },
  app_channels::{
      api::tangle::{
          Subscriber as ApiSubscriber,
          Transport as _,
          ChannelAddress,
      },
  },
  core::{
      prelude::Rc,
      print,
      println,
  },
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
  subscriber: Rc<RefCell<ApiSubscriber<Rc<RefCell<Client>>>>>,
}

#[wasm_bindgen]
impl Subscriber {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, seed: String, options: SendTrytesOptions) -> Subscriber {
        let mut client = Client::new_from_url(&node);
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));

        let subscriber = Rc::new(RefCell::new(ApiSubscriber::new(&seed, "utf-8", PAYLOAD_BYTES, transport)));
        Subscriber { subscriber }
    }

    pub fn channel_address(&self) -> Result<String> {
        to_result(self.subscriber.borrow()
                  .channel_address()
                  .map(|addr| addr.to_string())
                  .ok_or("channel not subscribed")
        )
    }

    /*
    #[wasm_bindgen(catch)]
    pub async fn receive_announcement(self, link: String) -> Result<()> {
        to_result(self.subscriber.borrow_mut()
                  .receive_announcement(&ApiAddress::from_str(&link)?)
                  .await)
    }
     */
}
