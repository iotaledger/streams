use wasm_bindgen::prelude::*;

use crate::types::*;

use iota_streams::{
  app::{
      message::HasLink,
      transport::tangle::PAYLOAD_BYTES,
  },
  app_channels::{
      api::tangle::{
          Subscriber,
          Transport,
          Address,
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
      tangle::client::{SendTrytesOptions, Client, },
  },
  core::prelude::{ String,  },
};

#[wasm_bindgen]
pub struct SubscriberW {
  subscriber: Subscriber<Rc<RefCell<Client>>>,
}

#[wasm_bindgen]
impl SubscriberW {
  #[wasm_bindgen(constructor)]
  pub fn new(node: String, seed: String, options: SendTrytesOptionsW) -> SubscriberW {
    let client = Client::new_from_url(&node);

    let mut transport = Rc::new(RefCell::new(client));

    transport.set_send_options(SendTrytesOptions {
      depth: options.depth,
      min_weight_magnitude: options.min_weight_magnitude,
      local_pow: options.local_pow,
      threads: options.threads,
    });

    let subscriber = Subscriber::new(&seed, "utf-8", PAYLOAD_BYTES, transport);

    SubscriberW { subscriber: subscriber }
  }
}
