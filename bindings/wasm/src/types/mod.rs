use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct SendTrytesOptionsW {
    pub depth: u8,
    pub min_weight_magnitude: u8,
    pub local_pow: bool,
    pub threads: usize,
}

#[wasm_bindgen]
impl SendTrytesOptionsW {
    #[wasm_bindgen(constructor)]
    pub fn new(depth: u8, min_weight_magnitude: u8, local_pow: bool, threads: usize) -> SendTrytesOptionsW {
        SendTrytesOptionsW {
            depth: depth,
            min_weight_magnitude: min_weight_magnitude,
            local_pow: local_pow,
            threads: threads,
        }
   }
}

#[wasm_bindgen]
pub struct AddressW {
    addr_id: String, 
    msg_id: String
}

#[wasm_bindgen]
impl AddressW {
    #[wasm_bindgen(getter)]
    pub fn addr_id(&self) -> String {
        self.addr_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_addr_id(&mut self, addr_id: String) {
        self.addr_id = addr_id;
    }

    #[wasm_bindgen(getter)]
    pub fn msg_id(&self) -> String {
        self.msg_id.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_msg_id(&mut self, msg_id: String) {
        self.msg_id = msg_id;
    }
}