use wasm_bindgen::prelude::*;

use crate::types::*;

/// Streams imports
use iota_streams::{
    app::{
        message::HasLink,
        transport::tangle::PAYLOAD_BYTES,
    },
    app_channels::{
        api::tangle::{
            Author,
            Transport,
            Address,
            ChannelAddress
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
pub struct AuthorW {
  author: Author<Rc<RefCell<Client>>>,
}

#[wasm_bindgen]
impl AuthorW {
  #[wasm_bindgen(constructor)]
  pub fn new(node: String, seed: String, options: SendTrytesOptionsW, multi_branching: bool) -> AuthorW {
    //let node = "https://nodes.devnet.iota.org:443"; //"https://nodes.devnet.iota.org:443";

    let client = Client::new_from_url(&node);

    let mut transport = Rc::new(RefCell::new(client));
    
    transport.set_send_options(SendTrytesOptions {
      depth: options.depth,
      min_weight_magnitude: options.min_weight_magnitude,
      local_pow: options.local_pow,
      threads: options.threads,
    });

    let author = Author::new(&seed, "utf-8", PAYLOAD_BYTES, multi_branching, transport);

    AuthorW { author: author }
  }

  //channel_address_t
  pub fn channel_address(&self) -> Result<String, JsValue> {
      let ch_addr = self.author.channel_address().unwrap();
      Ok(ch_addr.to_string().to_owned())
  }
  //uint8_t
  pub fn is_multi_branching(&self) -> Result<bool, JsValue> {
    Ok(self.author.is_multi_branching())
  }
  //public_key_t
  pub fn get_public_key(&self) -> Result<String, JsValue> {
    Ok("pk".to_owned())
  }
  
  /*// Announce
  pub fn address_t const *auth_send_announce(author_t *author) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  // Subscribe
  pub fn void *auth_receive_subscribe(author_t *author, address_t const *address) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  // Keyload
  pub fn message_links_t auth_send_keyload(author_t *author, address_t const *link_to, psk_ids_t *psk_ids, ke_pks_t ke_pks) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  
  pub fn message_links_t auth_send_keyload_for_everyone(author_t *author, address_t const *link_to) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  // Tagged Packets
  pub fn message_links_t auth_send_tagged_packet(author_t *author, message_links_t link_to, uint8_t const *public_payload_ptr, size_t public_payload_size, uint8_t const *masked_payload_ptr, size_t masked_payload_size) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  pub fn packet_payloads_t auth_receive_tagged_packet(author_t *author, address_t const *address) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  // Signed Packets
  pub fn message_links_t auth_send_signed_packet(author_t *author, message_links_t link_to, uint8_t const *public_payload_ptr, size_t public_payload_size, uint8_t const *masked_payload_ptr, size_t masked_payload_size) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  pub fn packet_payloads_t auth_receive_tagged_packet(author_t *author, address_t const *address)  -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  // Sequence Message (for multi branch use)
  pub fn address_t const *auth_receive_sequence(author_t *author, address_t const *address) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  // MsgId generation
  pub fn fn tern next_msg_ids_t const *auth_gen_next_msg_ids(author_t *author) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  // Generic Processing
  pub fn unwrapped_message_t const *auth_receive_msg(author_t *author, address_t const *address) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  // Fetching/Syncing
  pub fn unwrapped_messages_t const *auth_fetch_next_msgs(author_t *author) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }
  pub fn unwrapped_messages_t const *auth_sync_state(author_t *author) -> Result<String, JsValue> {
    Ok(seed.to_owned())
  }*/
}