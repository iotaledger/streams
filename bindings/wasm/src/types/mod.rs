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