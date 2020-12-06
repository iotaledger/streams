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
pub struct AuthorW {
    author: Author<Rc<RefCell<Client>>>,
}

#[wasm_bindgen]
impl AuthorW {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, seed: String, options: SendTrytesOptionsW, multi_branching: bool) -> AuthorW {
        let node = "https://nodes.devnet.iota.org:443";

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

    pub fn timestamp(&self) -> f64 {
        js_sys::Date::new_0().value_of()
        //chrono::Utc::now().timestamp_millis() as f64
    }

    pub fn channel_address(&self) -> Result<String, JsValue> {
        let ch_addr = self.author.channel_address().unwrap();
        Ok(ch_addr.to_string().to_owned())
    }

    pub fn is_multi_branching(&self) -> Result<bool, JsValue> {
        Ok(self.author.is_multi_branching())
    }

    pub fn get_public_key(&self) -> Result<String, JsValue> {
        Ok("pk".to_owned())
    }

    pub fn auth_send_announce(&mut self) -> Result<String, JsValue> {
        let announce = self.author.send_announce().unwrap();
        Ok(announce.to_string().to_owned())
    }

    pub fn receive_subscribe(&mut self, link_to: AddressW) -> Result<(), JsValue> {
        let addr = Address::from_str(&link_to.addr_id(), &link_to.msg_id()).unwrap();
        // Errors on missing functions from iota-core/iota-client/ureq/rustls/ring in the env
        //self.author.receive_subscribe(&addr).unwrap();
        Ok(())
    }

    pub fn send_keyload_for_everyone(&mut self, link_to: AddressW) -> Result<String, JsValue> {
        let addr = Address::from_str(&link_to.addr_id(), &link_to.msg_id()).unwrap();
        let keyload_id = self.author.send_keyload_for_everyone(&addr).unwrap();
        Ok(keyload_id.0.to_string().to_owned())
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
    pub fn fetch_next_msgs(&self) -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }

    // unwrapped_messages_t
    pub fn sync_state(&self) -> Result<String, JsValue> {
        Ok(seed.to_owned())
    }
    */
}
