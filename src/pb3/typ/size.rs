//! This module describes PB3 `size_t` type and relevant commands over it.

use crate::pb3::cmd::{
    absorb::{Absorb, WrapAbsorb},
    mask::{Mask, WrapMask},
    wrp::{Unwrap, Wrap},
};
use crate::pb3::err::{guard, Err, Result};
use crate::spongos::Spongos;
use crate::trits::{self, TritSlice, TritSliceMut};

/// PB3 `size_t` type, unsigned.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct Size(pub usize);

/// Max value of `size_t` type: `(27^13 - 1) / 2`.
const SIZE_MAX: usize = 2_026_277_576_509_488_133;

/// Number of trytes needed to encode a value of `size_t` type.
fn size_trytes(n: usize) -> usize {
    // Larger values wouldn't fit into max of 13 trytes.
    assert!(n <= SIZE_MAX);

    // `(27^12 - 1) / 2`.
    const M12: usize = 75_047_317_648_499_560;
    if n > M12 {
        // Handle special case in order to avoid overflow in `m` below.
        return 13;
    }

    let mut d: usize = 0;
    let mut m: usize = 1;
    while n > (m - 1) / 2 {
        // Can't overflow.
        m *= 27;
        d += 1;
    }

    d
}

pub fn sizeof_sizet(n: usize) -> usize {
    3 * (size_trytes(n) + 1)
}

/// A value of `size_t` can be absorbed and masked.
impl Size {
    /// The number of *trits* in the codeword.
    pub fn sizeof(&self) -> usize {
        sizeof_sizet(self.0)
    }

    /// Wrap the number of trytes in the representation.
    fn wrap_head(w: &mut dyn Wrap, b: &mut TritSliceMut, d: usize) {
        w.wrap3(b, d as trits::Trint3);
    }

    /// Wrap the representation value trytes.
    fn wrap_tail(w: &mut dyn Wrap, b: &mut TritSliceMut, d: usize, mut n: usize) {
        for _ in 0..d {
            let (r, q) = trits::mods3_usize(n);
            w.wrap3(b, r);
            n = q;
        }
    }

    /// Wrap the value.
    /// TODO: use different wrappers for `wrap_head` and `wrap_tail`? For example, `absorb` head and `encr` tail.
    fn wrap(&self, w: &mut dyn Wrap, b: &mut TritSliceMut) {
        let d = size_trytes(self.0);
        Self::wrap_head(w, b, d);
        let n: usize = self.0;
        Self::wrap_tail(w, b, d, n);
    }

    /// Unwrap the number of trytes in the representation.
    fn unwrap_head(w: &mut dyn Unwrap, b: &mut TritSlice) -> Result<usize> {
        guard(3 <= b.size(), Err::Eof)?;

        let d = w.unwrap3(b)?;
        guard(0 <= d && d <= 13, Err::BadValue)?;

        Ok(d as usize)
    }

    /// Unwrap the representation value trytes.
    fn unwrap_tail(w: &mut dyn Unwrap, b: &mut TritSlice, mut d: usize) -> Result<usize> {
        guard(3 * d <= b.size(), Err::Eof)?;

        let mut m: i64 = 0;
        let mut r: i64 = 1;
        if 0 < d {
            d -= 1;
            let mut t = w.unwrap3(b)?;
            m = t as i64;

            while 0 < d {
                d -= 1;
                t = w.unwrap3(b)?;
                r *= 27;
                m += r * t as i64;
            }

            // The last most significant trint3 can't be 0 or negative.
            guard(0 < t, Err::BadValue)?;

            // TODO: Can there be an overflow here?
            guard(SIZE_MAX >= m as usize, Err::BadValue)?;
        }

        Ok(m as usize)
    }

    /// Unwrap the value.
    fn unwrap(w: &mut dyn Unwrap, b: &mut TritSlice) -> Result<Self> {
        let d = Self::unwrap_head(w, b)?;
        let n = Self::unwrap_tail(w, b, d)?;
        Ok(Self(n))
    }
}

impl Absorb for Size {
    /// `absorb` during wrapping.
    fn wrap_absorb(&self, s: &mut Spongos, b: &mut TritSliceMut) {
        self.wrap(&mut WrapAbsorb { s }, b);
    }

    /// `absorb` during unwrapping.
    fn unwrap_absorb_sized(s: &mut Spongos, b: &mut TritSlice) -> Result<Self> {
        Self::unwrap(&mut WrapAbsorb { s }, b)
    }
}

impl Mask for Size {
    /// `mask`(`encr`) during wrapping.
    fn wrap_mask(&self, s: &mut Spongos, b: &mut TritSliceMut) {
        self.wrap(&mut WrapMask { s }, b);
    }

    /// `mask`(`decr`) during unwrapping.
    fn unwrap_mask_sized(s: &mut Spongos, b: &mut TritSlice) -> Result<Self> {
        Self::unwrap(&mut WrapMask { s }, b)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::trits::Trits;

    fn size_absorb_wrap_unwrap(t: Size, sw: &mut Spongos, su: &mut Spongos) {
        let mut buf = Trits::zero(t.sizeof());
        {
            let mut b = buf.slice_mut();
            t.wrap_absorb(sw, &mut b);
        }
        {
            let mut b = buf.slice();
            let r = Size::unwrap_absorb_sized(su, &mut b);
            assert!(r.is_ok());
            let tu = r.unwrap();
            assert_eq!(t, tu);
        }
    }

    fn size_mask_wrap_unwrap(t: Size, sw: &mut Spongos, su: &mut Spongos) {
        let mut buf = Trits::zero(t.sizeof());
        {
            let mut b = buf.slice_mut();
            t.wrap_mask(sw, &mut b);
        }
        {
            let mut b = buf.slice();
            let r = Size::unwrap_mask_sized(su, &mut b);
            assert!(r.is_ok());
            let tu = r.unwrap();
            assert_eq!(t, tu);
        }
    }

    #[test]
    fn absorb_wrap_unwrap() {
        let mut sw = Spongos::init();
        let mut su = Spongos::init();

        // Absorb key, randomize state.
        {
            let k = Trits::from_str("KEY").unwrap();
            sw.absorb_trits(&k);
            sw.commit();
            su.absorb_trits(&k);
            su.commit();
        }

        let ns = [
            0,
            1,
            13,
            14,
            25,
            26,
            27,
            39,
            40,
            81,
            9840,
            9841,
            9842,
            19683,
            SIZE_MAX - 1,
            SIZE_MAX,
        ];
        for n in ns.iter() {
            size_absorb_wrap_unwrap(Size(*n), &mut sw, &mut su);
        }

        sw.commit();
        su.commit();
        assert_eq!(sw.squeeze_trits(243), su.squeeze_trits(243));
    }

    #[test]
    fn mask_wrap_unwrap() {
        let mut sw = Spongos::init();
        let mut su = Spongos::init();

        // Absorb key, randomize state.
        {
            let k = Trits::from_str("KEY").unwrap();
            sw.absorb_trits(&k);
            sw.commit();
            su.absorb_trits(&k);
            su.commit();
        }

        let ns = [
            0,
            1,
            13,
            14,
            25,
            26,
            27,
            39,
            40,
            81,
            9840,
            9841,
            9842,
            19683,
            SIZE_MAX - 1,
            SIZE_MAX,
        ];
        for n in ns.iter() {
            size_mask_wrap_unwrap(Size(*n), &mut sw, &mut su);
        }

        sw.commit();
        su.commit();
        assert_eq!(sw.squeeze_trits(243), su.squeeze_trits(243));
    }
}
