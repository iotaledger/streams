use iota_streams_core::{
    sponge::prp::{
        inner,
        PRP,
    },
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

impl From<Vec<u8>> for KeccakF1600
{
    fn from(v: Vec<u8>) -> Self {
        panic!("not implemented");
    }
}

impl PRP for KeccakF1600
{
    const RATE: usize = (1600 - 256) / 8;

    const CAPACITY_BITS: usize = 256;

    fn transform(&mut self, outer: &mut [u8]) {
        unsafe {
            let s = std::mem::transmute::<&mut [u64], &mut [u8]>(&mut self.state);
            xor(&mut s[..Self::RATE], &outer[..]);
        }
        keccak::f1600(&mut self.state);
        unsafe {
            let s = std::mem::transmute::<&[u64], &[u8]>(&mut self.state);
            xor(outer, &s[..Self::RATE]);
        }
    }
}
