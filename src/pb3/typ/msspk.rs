//! PB3 `tryte[]` and `trytes` types and corresponding commands.

use crate::mss;
use crate::pb3::cmd::{absorb::Absorb, mask::Mask};
use crate::pb3::err::Result;
use crate::spongos::Spongos;
use crate::trits::{TritSlice, TritSliceMut, Trits};

impl Absorb for mss::PublicKey {
    fn wrap_absorb(&self, s: &mut Spongos, b: &mut TritSliceMut) {
        self.pk.wrap_absorb(s, b)
    }

    fn unwrap_absorb(&mut self, s: &mut Spongos, b: &mut TritSlice) -> Result<()> {
        self.pk.unwrap_absorb(s, b)
    }

    fn unwrap_absorb_sized(s: &mut Spongos, b: &mut TritSlice) -> Result<Self> {
        let mut pk = Trits::zero(mss::PK_SIZE);
        pk.unwrap_absorb(s, b)?;
        Ok(mss::PublicKey { pk })
    }
}

impl Mask for mss::PublicKey {
    fn wrap_mask(&self, s: &mut Spongos, b: &mut TritSliceMut) {
        self.pk.wrap_mask(s, b)
    }

    fn unwrap_mask(&mut self, s: &mut Spongos, b: &mut TritSlice) -> Result<()> {
        self.pk.unwrap_mask(s, b)
    }

    fn unwrap_mask_sized(s: &mut Spongos, b: &mut TritSlice) -> Result<Self> {
        let mut pk = Trits::zero(mss::PK_SIZE);
        pk.unwrap_mask(s, b)?;
        Ok(mss::PublicKey { pk })
    }
}
