use iota_streams_core::{
    prelude::Vec,
    sponge::prp::PRP,
};
use keccak;

#[derive(Clone)]
pub struct KeccakF1600 {
    state: [u64; 25],
}

impl Default for KeccakF1600 {
    fn default() -> Self {
        Self { state: [0u64; 25] }
    }
}

impl KeccakF1600 {
    pub fn permutation(&mut self) {
        keccak::f1600(&mut self.state);
    }
}

fn xor(s: &mut [u8], x: &[u8]) {
    for (si, xi) in s.iter_mut().zip(x.iter()) {
        *si ^= *xi;
    }
}

impl From<Vec<u8>> for KeccakF1600 {
    fn from(v: Vec<u8>) -> Self {
        assert_eq!(200, v.len());
        let mut s = Self::default();
        unsafe {
            let t = core::slice::from_raw_parts_mut(s.state.as_mut_ptr() as *mut u8, 200);
            t.copy_from_slice(&v[..]);
        }
        s
    }
}

impl Into<Vec<u8>> for KeccakF1600 {
    fn into(self) -> Vec<u8> {
        let mut v = vec![0_u8; 200];
        unsafe {
            let t = core::slice::from_raw_parts(self.state.as_ptr() as *const u8, 200);
            v.copy_from_slice(t);
        }
        v
    }
}

impl PRP for KeccakF1600 {
    const RATE: usize = (1600 - 256) / 8;

    const CAPACITY_BITS: usize = 256;

    fn transform(&mut self, outer: &mut [u8]) {
        unsafe {
            let s = core::slice::from_raw_parts_mut(self.state.as_mut_ptr() as *mut u8, Self::RATE);
            xor(s, &outer[..]);
        }
        keccak::f1600(&mut self.state);
        unsafe {
            let s = core::slice::from_raw_parts(self.state.as_ptr() as *const u8, Self::RATE);
            xor(outer, s);
        }
    }
}
