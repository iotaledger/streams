use crate::ntru;
use crate::pb3::cmd::{absorb::{Absorb}, mask::{Mask}};
use crate::pb3::err::{Err, guard, Result};
use crate::poly::{Poly};
use crate::spongos::{Spongos};
use crate::trits::{TritConstSlice, TritMutSlice, Trits};

impl Absorb for ntru::PublicKey {
    fn wrap_absorb(&self, s: &mut Spongos, b: &mut TritMutSlice) {
        self.pk.wrap_absorb(s, b)
    }

    fn unwrap_absorb(&mut self, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
        self.pk.unwrap_absorb(s, b)?;
        guard(self.validate(), Err::NtruBadPublicKey)
    }

    fn unwrap_absorb_sized(s: &mut Spongos, b: &mut TritConstSlice) -> Result<Self> {
        let mut t = Trits::zero(ntru::PK_SIZE);
        t.unwrap_absorb(s, b)?;
        ntru::PublicKey::from_trits(t).ok_or(Err::NtruBadPublicKey)
    }
}

impl Mask for ntru::PublicKey {
    fn wrap_mask(&self, s: &mut Spongos, b: &mut TritMutSlice) {
        self.pk.wrap_mask(s, b)
    }

    fn unwrap_mask(&mut self, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
        self.pk.unwrap_mask(s, b)?;
        guard(self.validate(), Err::NtruBadPublicKey)
    }

    fn unwrap_mask_sized(s: &mut Spongos, b: &mut TritConstSlice) -> Result<Self> {
        let mut t = Trits::zero(ntru::PK_SIZE);
        t.unwrap_mask(s, b)?;
        ntru::PublicKey::from_trits(t).ok_or(Err::NtruBadPublicKey)
    }
}
