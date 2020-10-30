use wasm_bindgen::prelude::*;


#[wasm_bindgen]
extern "C" {
  #[wasm_bindgen(js_namespace = console)]
  pub fn log(s: &str);
  #[wasm_bindgen(js_namespace = console)]
  pub fn error(s: &str);
}

#[wasm_bindgen(js_name = "Greet")]
pub fn greet() -> Result<String, JsValue> {
  console_error_panic_hook::set_once();

  Ok("Hello World!".to_owned())
}

use iota_streams::{
  app::{
      message::HasLink,
      transport::tangle::PAYLOAD_BYTES,
  },
  app_channels::{
      api::tangle::{
          Author,
          Transport,
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

/// creates and returns autor object
#[wasm_bindgen]
pub fn auth_new(seed: String) -> Result<String, JsValue> {
  console_error_panic_hook::set_once();

  let node = "https://nodes.devnet.iota.org:443"; //"https://nodes.devnet.iota.org:443";

  let client = Client::new_from_url(node);

  let mut transport = Rc::new(RefCell::new(client));
  let mut send_opt = SendTrytesOptions::default();
  send_opt.min_weight_magnitude = 14;
  transport.set_send_options(send_opt);

  //let client = unsafe { (*transport).clone() };

  let author = Author::new(&seed, "utf-8", PAYLOAD_BYTES, false, transport);


  Ok(seed.to_owned())
}
