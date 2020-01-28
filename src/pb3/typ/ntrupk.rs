use crate::ntru;
use crate::pb3::cmd::{absorb::Absorb, mask::Mask};
use crate::pb3::err::{guard, Err, Result};
use crate::spongos::Spongos;
use crate::trits::{TritSlice, TritSliceMut, Trits};

impl Absorb for ntru::PublicKey {
    fn wrap_absorb(&self, s: &mut Spongos, b: &mut TritSliceMut) {
        self.pk.wrap_absorb(s, b)
    }

    fn unwrap_absorb(&mut self, s: &mut Spongos, b: &mut TritSlice) -> Result<()> {
        self.pk.unwrap_absorb(s, b)?;
        guard(self.validate(), Err::NtruBadPublicKey)
    }

    fn unwrap_absorb_sized(s: &mut Spongos, b: &mut TritSlice) -> Result<Self> {
        let mut t = Trits::zero(ntru::PK_SIZE);
        t.unwrap_absorb(s, b)?;
        ntru::PublicKey::from_trits(t).ok_or(Err::NtruBadPublicKey)
    }
}

impl Mask for ntru::PublicKey {
    fn wrap_mask(&self, s: &mut Spongos, b: &mut TritSliceMut) {
        self.pk.wrap_mask(s, b)
    }

    fn unwrap_mask(&mut self, s: &mut Spongos, b: &mut TritSlice) -> Result<()> {
        self.pk.unwrap_mask(s, b)?;
        guard(self.validate(), Err::NtruBadPublicKey)
    }

    fn unwrap_mask_sized(s: &mut Spongos, b: &mut TritSlice) -> Result<Self> {
        let mut t = Trits::zero(ntru::PK_SIZE);
        t.unwrap_mask(s, b)?;
        ntru::PublicKey::from_trits(t).ok_or(Err::NtruBadPublicKey)
    }
}
