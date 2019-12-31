//! PB3 `tryte[]` and `trytes` types and corresponding commands.

use crate::pb3::cmd::{absorb::{Absorb}, mask::{Mask}};
use crate::pb3::err::{Err, guard, Result};
use crate::pb3::typ::size::{Size, sizeof_sizet};
use crate::spongos::{Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

/// PB3 `tryte [n]` type.
/// NB. `trytes` is a composite type. These two constructs are equivalent:
/// ```pb3
/// ctl trytes x;
/// ```
/// and
/// ```pb3
/// absorb size_t n;
/// ctl tryte x[n];
/// ```
/// where `ctl` is either `absorb` (by default), or `mask`.
pub type NTrytes = trits::Trits;
#[derive(PartialEq,Eq,Clone,Debug)]
pub struct Trytes(pub trits::Trits);

impl Trytes {
    pub fn size(&self) -> usize {
        self.0.size()
    }
}

pub fn sizeof_ntrytes(n: usize) -> usize {
    3 * n
}

pub fn sizeof_trytes(n: usize) -> usize {
    sizeof_sizet(n) + sizeof_ntrytes(n)
}

impl Trytes {
    pub fn sizeof(n: usize) -> usize {
        Size(n).sizeof() + 3 * n
    }
}

pub fn wrap_absorb_trits(x: TritConstSlice, s: &mut Spongos, b: &mut TritMutSlice) {
    let n = x.size();
    assert!(n <= b.size());
    let t = b.advance(n);
    x.copy(t);
    s.absorb(x);
}

pub fn unwrap_absorb_trits(x: TritMutSlice, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
    let n = x.size();
    guard(n <= b.size(), Err::Eof)?;
    let t = b.advance(n);
    t.copy(x);
    s.absorb(x.as_const());
    Ok(())
}

pub fn unwrap_absorb_n(n: usize, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
    guard(n <= b.size(), Err::Eof)?;
    s.absorb(b.advance(n));
    Ok(())
}

pub fn wrap_mask_trits(x: TritConstSlice, s: &mut Spongos, b: &mut TritMutSlice) {
    let n = x.size();
    assert!(n <= b.size());
    let t = b.advance(n);
    s.encr(x, t);
}

pub fn unwrap_mask_trits(x: TritMutSlice, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
    let n = x.size();
    guard(n <= b.size(), Err::Eof)?;
    let t = b.advance(n);
    s.decr(t, x);
    Ok(())
}

pub fn wrap_absorb_trytes(x: &Trits, s: &mut Spongos, b: &mut TritMutSlice) {
    assert!(x.size() % 3 == 0);
    Size(x.size() / 3).wrap_absorb(s, b);
    wrap_absorb_trits(x.slice(), s, b);
}

pub fn unwrap_absorb_trytes(s: &mut Spongos, b: &mut TritConstSlice) -> Result<Trits> {
    let n = Size::unwrap_absorb_sized(s, b)?;
    let mut x = Trits::zero(n.0 * 3);
    unwrap_absorb_trits(x.mut_slice(), s, b)?;
    Ok(x)
}

pub fn wrap_mask_trytes(x: &Trits, s: &mut Spongos, b: &mut TritMutSlice) {
    assert!(x.size() % 3 == 0);
    Size(x.size() / 3).wrap_mask(s, b);
    wrap_mask_trits(x.slice(), s, b);
}

pub fn unwrap_mask_trytes(s: &mut Spongos, b: &mut TritConstSlice) -> Result<Trits> {
    let n = Size::unwrap_mask_sized(s, b)?;
    let mut x = Trits::zero(n.0 * 3);
    unwrap_mask_trits(x.mut_slice(), s, b)?;
    Ok(x)
}

impl Absorb for NTrytes {

    /// `copy` and `absorb` trits.
    fn wrap_absorb(&self, s: &mut Spongos, b: &mut TritMutSlice) {
        wrap_absorb_trits(self.slice(), s, b)
    }

    /// `copy` and `absorb` trits.
    fn unwrap_absorb(&mut self, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
        unwrap_absorb_trits(self.mut_slice(), s, b)
    }

    fn unwrap_absorb_sized(_s: &mut Spongos, _b: &mut TritConstSlice) -> Result<Self> {
        // Size unknown - method can't be called.
        Err(Err::InternalError)
    }
}

impl Mask for NTrytes {

    /// `encr` trits.
    fn wrap_mask(&self, s: &mut Spongos, b: &mut TritMutSlice) {
        wrap_mask_trits(self.slice(), s, b)
    }

    /// `decr` codeword into a temp buffer and `decode` value.
    fn unwrap_mask(&mut self, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
        unwrap_mask_trits(self.mut_slice(), s, b)
    }

    fn unwrap_mask_sized(_s: &mut Spongos, _b: &mut TritConstSlice) -> Result<Self> {
        // size unknown; this should be internal error - method can't be called
        Err(Err::BadValue)
    }
}

impl Absorb for Trytes {

    /// Absorb size and trytes.
    fn wrap_absorb(&self, s: &mut Spongos, b: &mut TritMutSlice) {
        wrap_absorb_trytes(&self.0, s, b);
    }

    /// Absorb size and trytes.
    fn unwrap_absorb(&mut self, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
        let x = unwrap_absorb_trytes(s, b)?;
        self.0 = x;
        Ok(())
    }

    /// Decode and absorb size and trytes.
    fn unwrap_absorb_sized(s: &mut Spongos, b: &mut TritConstSlice) -> Result<Self> {
        let x = unwrap_absorb_trytes(s, b)?;
        Ok(Self(x))
    }
}

impl Mask for Trytes {

    /// Encr size and trytes.
    /// Note, in MAM1 was: absorb size and encr trytes.
    fn wrap_mask(&self, s: &mut Spongos, b: &mut TritMutSlice) {
        wrap_mask_trytes(&self.0, s, b);
    }

    /// Decr size and trytes.
    /// Note, in MAM1 was: absorb size and decr trytes.
    fn unwrap_mask(&mut self, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
        self.0 = unwrap_mask_trytes(s, b)?;
        Ok(())
    }

    /// Decr size and trytes.
    /// Note, in MAM1 was: absorb size and decr trytes.
    fn unwrap_mask_sized(s: &mut Spongos, b: &mut TritConstSlice) -> Result<Self> {
        let x = unwrap_mask_trytes(s, b)?;
        Ok(Self(x))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::prng;

    const NS: [usize; 10] = [0, 1, 13, 26, 27, 243, 486, 487, 1000, 2000];

    fn gen_trits(n: usize) -> Trits {
        prng::dbg_init_str("KEY").gen_trits(&Trits::from_str("PRNGNONCE").unwrap(), n)
    }

    fn init_ss() -> (Spongos, Spongos) {
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

        (sw, su)
    }

    fn check_ss(ss: (Spongos, Spongos)) {
        let (mut su, mut sw) = ss;
        sw.commit();
        su.commit();
        assert_eq!(sw.squeeze_trits(243), su.squeeze_trits(243));
    }
    
    fn ntrytes_absorb_wrap_unwrap_n(n: usize, sw: &mut Spongos, su: &mut Spongos) {
        let t = gen_trits(n);
        let mut buf = Trits::zero(n); // sizeof_ntrytes(n / 3)
        {
            let mut b = buf.mut_slice();
            t.wrap_absorb(sw, &mut b);
        }
        {
            let mut b = buf.slice();
            let mut tu = Trits::zero(n);
            let r = tu.unwrap_absorb(su, &mut b);
            assert!(r.is_ok());
            assert_eq!(t, tu);
        }
    }
    
    fn ntrytes_mask_wrap_unwrap_n(n: usize, sw: &mut Spongos, su: &mut Spongos) {
        let t = gen_trits(n);
        let mut buf = Trits::zero(n); // sizeof_ntrytes(n / 3)
        {
            let mut b = buf.mut_slice();
            t.wrap_mask(sw, &mut b);
        }
        {
            let mut b = buf.slice();
            let mut tu = Trits::zero(n);
            let r = tu.unwrap_mask(su, &mut b);
            assert!(r.is_ok());
            assert_eq!(t, tu);
        }
    }

    fn trytes_absorb_wrap_unwrap_n(n: usize, sw: &mut Spongos, su: &mut Spongos) {
        let t = Trytes(gen_trits(n));
        let mut buf = Trits::zero(sizeof_trytes(n / 3));
        {
            let mut b = buf.mut_slice();
            t.wrap_absorb(sw, &mut b);
        }
        {
            let mut b = buf.slice();
            let r = Trytes::unwrap_absorb_sized(su, &mut b);
            assert!(r.is_ok());
            let tu = r.unwrap();
            assert_eq!(t, tu);
        }
    }

    fn trytes_mask_wrap_unwrap_n(n: usize, sw: &mut Spongos, su: &mut Spongos) {
        let t = Trytes(gen_trits(n));
        let mut buf = Trits::zero(sizeof_trytes(n / 3));
        {
            let mut b = buf.mut_slice();
            t.wrap_mask(sw, &mut b);
        }
        {
            let mut b = buf.slice();
            let r = Trytes::unwrap_mask_sized(su, &mut b);
            assert!(r.is_ok());
            let tu = r.unwrap();
            assert_eq!(t, tu);
        }
    }
    
    #[test]
    fn ntrytes_absorb_wrap_unwrap() {
        let (mut sw, mut su) = init_ss();
        for n in NS.iter() {
            ntrytes_absorb_wrap_unwrap_n(*n, &mut sw, &mut su);
        }
        check_ss((su, sw));
    }

    #[test]
    fn ntrytes_mask_wrap_unwrap() {
        let (mut sw, mut su) = init_ss();
        for n in NS.iter() {
            ntrytes_mask_wrap_unwrap_n(*n, &mut sw, &mut su);
        }
        check_ss((su, sw));
    }

    #[test]
    fn trytes_absorb_wrap_unwrap() {
        let (mut sw, mut su) = init_ss();
        for n in NS.iter() {
            trytes_absorb_wrap_unwrap_n(*n /3 *3, &mut sw, &mut su);
        }
        check_ss((su, sw));
    }

    #[test]
    fn trytes_mask_wrap_unwrap() {
        let (mut sw, mut su) = init_ss();
        for n in NS.iter() {
            trytes_mask_wrap_unwrap_n(*n /3 *3, &mut sw, &mut su);
        }
        check_ss((su, sw));
    }
}
