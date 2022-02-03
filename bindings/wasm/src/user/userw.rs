use core::cell::RefCell;

use wasm_bindgen::prelude::*;

use crate::types::{Address, Details, ResultExt, SendOptions};

use client_wasm::client::Client as RustWasmClient;

use iota_streams::{
    app::transport::{
        tangle::client::{
            iota_client::Client as RustClient,
            Client as ApiClient,
        },
        TransportDetails,
        TransportOptions,
    },
    core::prelude::Rc,
};

#[wasm_bindgen]
#[derive(Clone)]
pub struct StreamsClient(pub(crate) Rc<RefCell<ApiClient>>);

#[wasm_bindgen]
impl StreamsClient {
    #[wasm_bindgen(constructor)]
    pub fn new(node: String, options: SendOptions) -> Self {
        let mut client = ApiClient::new_from_url(&node);
        client.set_send_options(options.into());
        let transport = Rc::new(RefCell::new(client));
        StreamsClient(transport)
    }

    #[wasm_bindgen(js_name = "fromClient")]
    pub fn from_client(client: &RustWasmClient) -> StreamsClient {
        let client = ApiClient::new(Default::default(), RustClient::clone(&client.into_inner()));
        let transport = Rc::new(RefCell::new(client));
        StreamsClient(transport)
    }

    pub fn get_link_details(mut self, link: &Address) -> js_sys::Promise {
        // wasm-bindgen does not honor Copy semantics in function parameters (see https://github.com/rustwasm/wasm-bindgen/issues/2204)
        // To workaround this limitation, we take a reference and copy it at the begining of the functions
        let link = *link;
        // Because we are passing `&Address` by reference, get_link_details cannot be an `async` function.
        // Neither can it return `impl Future` because of incompatibility with #[wasm_bindgen] internals.
        // The last resort is to convert manually to `JsValue` and then to `js_sys::Promise`
        wasm_bindgen_futures::future_to_promise(async move {
            self.0
                .get_link_details(link.as_inner())
                .await
                .map(Details::from)
                .map(JsValue::from)
                .into_js_result()
        })
    }
}

impl StreamsClient {
    #[allow(clippy::wrong_self_convention)]
    pub fn into_inner(self) -> Rc<RefCell<ApiClient>> {
        self.0
    }
}

impl From<ApiClient> for StreamsClient {
    fn from(client: ApiClient) -> Self {
        let transport = Rc::new(RefCell::new(client));
        StreamsClient(transport)
    }
}
