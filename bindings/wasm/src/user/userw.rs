use wasm_bindgen::prelude::*;

use crate::types::*;

use core::cell::RefCell;
use iota_streams::{
    app::transport::{
        tangle::client::Client as ApiClient,
        TransportOptions,
    },
    core::prelude::Rc,
};

#[wasm_bindgen]
#[derive(Clone)]
pub struct Client(ClientWrap);

#[wasm_bindgen]
impl Client {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, options: SendOptions) -> Self {
        let mut client = ApiClient::new_from_url(&node);
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));

        Client(transport)
    }
}

impl Client {
    pub fn to_inner(self) -> ClientWrap {
        self.0
    }
}

// impl From<Client> for ClientWrap {
// fn from(input: Client) -> Self {
// input.0
// }
// }
//
// impl Deref for Client {
// type Target = Rc<RefCell<ApiClient>>;
//
// fn deref(&self) -> &Self::Target {
// &self.0
// }
// }
