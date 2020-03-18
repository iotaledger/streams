use keccak;
use iota_mam_core::tbits::slice::TbitSliceMutT;
use iota_mam_core::tbits::binary::BitWord;
use iota_mam_core::sponge::prp::PRP;

#[derive(Clone)]
pub struct KeccakF1600{
    state: [u64; 25],
}

impl Default for KeccakF1600 {
    fn default() -> Self {
        Self {
            state: [0u64; 25],
        }
    }
}

impl KeccakF1600 {
    pub fn permutation(&mut self) {
        keccak::f1600(&mut self.state);
    }
}

impl<TW> PRP<TW> for KeccakF1600 where TW: BitWord {
    const RATE: usize = 1600 - 256;
    fn transform(&mut self, outer: &mut TbitSliceMutT<TW>) {
        //TODO: Copy from outer into self.state.
        self.permutation();
        //TODO: Copy from self.state into outer.
    }
}
