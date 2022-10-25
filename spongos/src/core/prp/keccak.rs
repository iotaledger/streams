use generic_array::{
    typenum::{U168, U32},
    GenericArray,
};

use super::PRP;

/// A psuedo-random permutation implementing `Keccak-F[1600]`
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeccakF1600 {
    /// Inner state for transformation
    state: [u64; 25],
}

impl KeccakF1600 {
    /// Use `Keccak-F[1600]` sponge function on inner state
    fn permutation(&mut self) {
        keccak::f1600(&mut self.state);
    }
}

impl PRP for KeccakF1600 {
    type RateSize = U168; // (1600 - 256) / 8

    type CapacitySize = U32; // 256

    fn transform(&mut self) {
        self.permutation();
    }

    fn outer(&self) -> &GenericArray<u8, Self::RateSize> {
        unsafe { &*(self.state.as_ptr() as *const GenericArray<u8, Self::RateSize>) }
    }

    fn outer_mut(&mut self) -> &mut GenericArray<u8, Self::RateSize> {
        unsafe { &mut *(self.state.as_mut_ptr() as *mut GenericArray<u8, Self::RateSize>) }
    }

    fn inner(&self) -> &GenericArray<u8, Self::CapacitySize> {
        unsafe { &*(self.state.as_ptr().add(21) as *const GenericArray<u8, Self::CapacitySize>) }
    }

    fn inner_mut(&mut self) -> &mut GenericArray<u8, Self::CapacitySize> {
        unsafe { &mut *(self.state.as_mut_ptr().add(21) as *mut GenericArray<u8, Self::CapacitySize>) }
    }
}
