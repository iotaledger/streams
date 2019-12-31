//! This module describes PB3 `trint3`, `trint6`, `trint9`, `trint18` integer types and relevant commands over them.

use crate::pb3::cmd::{absorb::{Absorb, WrapAbsorb}, mask::{Mask, WrapMask}, wrp::{Wrap, Unwrap}};
use crate::pb3::err::{Err, guard, Result};
use crate::spongos::{Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

/// A helper trait for integral types: `tryte`/`trint3`, `trint`/`trint6`, `trint9`, `trint18`.
/// A value of integral type has a fixed size and can be absorbed and masked.
pub trait TrintField where Self: Sized {

    /// The number of trits in the codeword.
    fn sizeof() -> usize;

    /// Encode the value into the buffer.
    fn encode(&self, b: &mut TritMutSlice);

    /// Decode the value from the buffer.
    fn decode(&mut self, b: &mut TritConstSlice) -> Result<()> {
        let v = Self::decode_sized(b)?;
        *self = v;
        Ok(())
    }

    /// Decode the value from the buffer.
    fn decode_sized(b: &mut TritConstSlice) -> Result<Self>;
}

impl<T> Absorb for T where T: TrintField {

    /// `encode` value and `absorb` codeword.
    fn wrap_absorb(&self, s: &mut Spongos, b: &mut TritMutSlice) {
        let b0 = *b;
        self.encode(b);
        s.absorb(b.diff(b0).as_const());
    }

    /// `decode` value and `absorb` codeword.
    fn unwrap_absorb_sized(s: &mut Spongos, b: &mut TritConstSlice) -> Result<Self> {
        let b0 = *b;
        let t = Self::decode_sized(b)?;
        s.absorb(b.diff(b0));
        Ok(t)
    }

}

impl<T> Mask for T where T: TrintField {

    /// `encode` value and `encr` codeword in-place.
    fn wrap_mask(&self, s: &mut Spongos, b: &mut TritMutSlice) {
        let b0 = *b;
        self.encode(b);
        let w = b.diff(b0);
        s.encr(w.as_const(), w);
    }

    /// `decr` codeword into a temp buffer and `decode` value.
    fn unwrap_mask_sized(s: &mut Spongos, b: &mut TritConstSlice) -> Result<Self> {
        let n = Self::sizeof();
        let mut t = trits::Trits::zero(n);
        s.decr(b.advance(n), t.mut_slice());
        Self::decode_sized(&mut t.slice())
    }
}

/// PB3 `tryte` type.
#[derive(PartialEq,Eq,Copy,Clone,Debug)]
pub struct Trint3(pub trits::Trint3);
pub type Tryte = Trint3;
pub fn tryte(t: trits::Trint3) -> Tryte {
    Trint3(t)
}

pub fn sizeof_tryte() -> usize { 3 }

impl TrintField for Trint3 {

    fn sizeof() -> usize {
        3
    }

    fn encode(&self, b: &mut TritMutSlice) {
        assert!(3 <= b.size());
        b.advance(3).put3(self.0);
    }

    fn decode_sized(b: &mut TritConstSlice) -> Result<Self> {
        guard(3 <= b.size(), Err::Eof)?;
        Ok(Self(b.advance(3).get3()))
    }
}

/// PB3 `tryte` type.
#[derive(PartialEq,Eq,Copy,Clone,Debug)]
pub struct Trint6(pub trits::Trint6);
pub type Trint = Trint6;

pub fn sizeof_trint() -> usize { 6 }

impl TrintField for Trint6 {

    fn sizeof() -> usize {
        6
    }

    fn encode(&self, b: &mut TritMutSlice) {
        assert!(6 <= b.size());
        b.advance(6).put6(self.0);
    }

    fn decode_sized(b: &mut TritConstSlice) -> Result<Self> {
        guard(6 <= b.size(), Err::Eof)?;
        Ok(Self(b.advance(6).get6()))
    }
}

/// PB3 `trint9` type.
#[derive(PartialEq,Eq,Copy,Clone,Debug)]
pub struct Trint9(pub trits::Trint9);

pub fn sizeof_trint9() -> usize { 9 }

impl TrintField for Trint9 {

    fn sizeof() -> usize {
        9
    }

    fn encode(&self, b: &mut TritMutSlice) {
        assert!(9 <= b.size());
        b.advance(9).put9(self.0);
    }

    fn decode_sized(b: &mut TritConstSlice) -> Result<Self> {
        guard(9 <= b.size(), Err::Eof)?;
        Ok(Self(b.advance(9).get9()))
    }
}

/// PB3 `trint18` type.
#[derive(PartialEq,Eq,Copy,Clone,Debug)]
pub struct Trint18(pub trits::Trint18);

impl TrintField for Trint18 {

    fn sizeof() -> usize {
        18
    }

    fn encode(&self, b: &mut TritMutSlice) {
        assert!(18 <= b.size());
        b.advance(18).put18(self.0);
    }

    fn decode_sized(b: &mut TritConstSlice) -> Result<Self> {
        guard(18 <= b.size(), Err::Eof)?;
        Ok(Self(b.advance(18).get18()))
    }
}

#[cfg(test)]
mod test {
    use std::fmt;
    use super::*;
    use crate::prng;

    fn trintx_absorb_wrap_unwrap<T>(t: T, sw: &mut Spongos, su: &mut Spongos) where T: TrintField + Eq + fmt::Debug {
        let mut buf = Trits::zero(T::sizeof());
        {
            let mut b = buf.mut_slice();
            t.wrap_absorb(sw, &mut b);
        }
        {
            let mut b = buf.slice();
            let r = T::unwrap_absorb_sized(su, &mut b);
            assert!(r.is_ok());
            let tu = r.unwrap();
            assert_eq!(t, tu);
        }
    }

    fn trintx_mask_wrap_unwrap<T>(t: T, sw: &mut Spongos, su: &mut Spongos) where T: TrintField + Eq + fmt::Debug {
        let mut buf = Trits::zero(T::sizeof());
        {
            let mut b = buf.mut_slice();
            t.wrap_mask(sw, &mut b);
        }
        {
            let mut b = buf.slice();
            let r = T::unwrap_mask_sized(su, &mut b);
            assert!(r.is_ok());
            let tu = r.unwrap();
            assert_eq!(t, tu);
        }
    }

    #[test]
    fn absorb_wrap_unwrap() {
        let mut sw = Spongos::init();
        let mut su = Spongos::init();

        trintx_absorb_wrap_unwrap(Trint3(0), &mut sw, &mut su);
        trintx_absorb_wrap_unwrap(Trint3(trits::MAX_TRINT3), &mut sw, &mut su);
        trintx_absorb_wrap_unwrap(Trint3(trits::MIN_TRINT3), &mut sw, &mut su);

        trintx_absorb_wrap_unwrap(Trint6(0), &mut sw, &mut su);
        trintx_absorb_wrap_unwrap(Trint6(trits::MAX_TRINT6), &mut sw, &mut su);
        trintx_absorb_wrap_unwrap(Trint6(trits::MIN_TRINT6), &mut sw, &mut su);

        trintx_absorb_wrap_unwrap(Trint9(0), &mut sw, &mut su);
        trintx_absorb_wrap_unwrap(Trint9(trits::MAX_TRINT9), &mut sw, &mut su);
        trintx_absorb_wrap_unwrap(Trint9(trits::MIN_TRINT9), &mut sw, &mut su);

        trintx_absorb_wrap_unwrap(Trint18(0), &mut sw, &mut su);
        trintx_absorb_wrap_unwrap(Trint18(trits::MAX_TRINT18), &mut sw, &mut su);
        trintx_absorb_wrap_unwrap(Trint18(trits::MIN_TRINT18), &mut sw, &mut su);

        sw.commit();
        su.commit();
        assert_eq!(sw.squeeze_trits(243), su.squeeze_trits(243));
    }

    #[test]
    fn mask_wrap_unwrap() {
        let mut sw = Spongos::init();
        let mut su = Spongos::init();

        trintx_mask_wrap_unwrap(Trint3(0), &mut sw, &mut su);
        trintx_mask_wrap_unwrap(Trint3(trits::MAX_TRINT3), &mut sw, &mut su);
        trintx_mask_wrap_unwrap(Trint3(trits::MIN_TRINT3), &mut sw, &mut su);

        trintx_mask_wrap_unwrap(Trint6(0), &mut sw, &mut su);
        trintx_mask_wrap_unwrap(Trint6(trits::MAX_TRINT6), &mut sw, &mut su);
        trintx_mask_wrap_unwrap(Trint6(trits::MIN_TRINT6), &mut sw, &mut su);

        trintx_mask_wrap_unwrap(Trint9(0), &mut sw, &mut su);
        trintx_mask_wrap_unwrap(Trint9(trits::MAX_TRINT9), &mut sw, &mut su);
        trintx_mask_wrap_unwrap(Trint9(trits::MIN_TRINT9), &mut sw, &mut su);

        trintx_mask_wrap_unwrap(Trint18(0), &mut sw, &mut su);
        trintx_mask_wrap_unwrap(Trint18(trits::MAX_TRINT18), &mut sw, &mut su);
        trintx_mask_wrap_unwrap(Trint18(trits::MIN_TRINT18), &mut sw, &mut su);

        sw.commit();
        su.commit();
        assert_eq!(sw.squeeze_trits(243), su.squeeze_trits(243));
    }
}
