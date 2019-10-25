use crate::trits::{TritWord, TritConstSlice, TritMutSlice};
use crate::spongos::{Spongos};
use crate::trits as trits;
use crate::spongos as spongos;

pub trait PB3<TW> {
    fn sizeof(&self) -> usize;
    fn encode(&self, b: &mut TritMutSlice<TW>) -> TritMutSlice<TW>;
    fn decode(&mut self, b: &mut TritConstSlice<TW>) -> Option<TritConstSlice<TW>>;
}

pub trait Absorb<TW>: where TW: TritWord + Copy, Self: PB3<TW> {
    fn wrap_absorb(&self, s: &mut Spongos<TW>, b: &mut TritMutSlice<TW>) {
        assert!(self.sizeof() <= b.size());
        s.absorb(self.encode(b).as_const());
    }
    fn unwrap_absorb(&mut self, s: &mut Spongos<TW>, b: &mut TritConstSlice<TW>) -> bool {
        if let Some(t) = self.decode(b) {
            s.absorb(t);
            true
        } else {
            false
        }
    }
}

pub trait Squeeze<TW>: where TW: TritWord + Copy, Self: PB3<TW> {
    fn wrap_squeeze(&mut self, s: &mut Spongos<TW>, b: &mut TritMutSlice<TW>) {
        assert!(self.sizeof() <= b.size());
        s.squeeze(b.take(self.sizeof()));
        *b = b.drop(self.sizeof());
    }
    fn unwrap_squeeze(&mut self, s: &mut Spongos<TW>, b: &mut TritConstSlice<TW>) -> bool {
        let mut p = trits::Trits::<TW>::zero(self.sizeof());
        s.squeeze(p.mut_slice());
        let t = b.take(self.sizeof());
        *b = b.drop(self.sizeof());
        if p.slice() == t {
            true
        } else {
            false
        }
    }
}

pub trait Crypt<TW>: where TW: TritWord + Copy, Self: PB3<TW> {
    fn wrap_encr(&mut self, s: &mut Spongos<TW>, b: &mut TritMutSlice<TW>) {
        assert!(self.sizeof() <= b.size());
        let t = self.encode(b);
        s.encr(t.as_const(), t);
        *b = b.drop(self.sizeof());
    }
    fn unwrap_decr(&mut self, s: &mut Spongos<TW>, b: &mut TritConstSlice<TW>) -> bool {
        let mut p = trits::Trits::<TW>::zero(self.sizeof());
        let t = b.take(self.sizeof());
        s.decr(t, p.mut_slice());
        *b = b.drop(self.sizeof());
        if let Some(_) = self.decode(&mut p.slice()) {
            p.mut_slice().set_zero();
            true
        } else {
            false
        }
    }
}

pub struct Size(usize);
pub struct Trint3(trits::Trint3);
pub struct Trint9(trits::Trint9);
pub struct Trint18(trits::Trint18);
pub struct Trits<TW>(trits::Trits<TW>);

const SIZE_MAX: usize = 2026277576509488133;
fn size_trytes(n: usize) -> usize {
    assert!(n <= SIZE_MAX);

    let mut d: usize = 0;
    let mut m: usize = 1;
    while n > (m - 1) / 2 {
        //TODO: handle overflow in m
        m *= 27;
        d += 1;
    }

    d
}

impl<TW> PB3<TW> for Size where TW: TritWord + Copy {
    fn sizeof(&self) -> usize {
        3 * (size_trytes(self.0) + 1)
    }
    fn encode(&self, b: &mut TritMutSlice<TW>) -> TritMutSlice<TW> {
        let begin = b.dropped_size();

        let d0 = size_trytes(self.0);
        let mut d = d0;
        b.advance(3).put3(d as trits::Trint3);

        let mut n: usize = self.0;
        if 27 < n {
            // explicitly unroll the first iteration safely
            d -= 1;
            let (r,q) = trits::mods3((n - 27) as i32);
            b.advance(3).put3(r);
            n = 1 + q as usize;
        }
        while 0 < d {
            d -= 1;
            let (r,q) = trits::mods3(n as i32);
            b.advance(3).put3(r);
            n = q as usize;
        }

        let end = b.dropped_size();
        assert!(3 * (d0 + 1) == end - begin);
        b.pickup(end - begin)
    }
    fn decode(&mut self, b: &mut TritConstSlice<TW>) -> Option<TritConstSlice<TW>>{
        let begin = b.dropped_size();
        
        loop {
            if !(3 <= b.size()) { break; } // ERR_PB3_EOF
            let mut d = b.advance(3).get3();
            if !(0 <= d && d <= 13) { break; } // ERR_INVALID_VALUE
            if !(3 * (d as usize) <= b.size()) { break; } // ERR_PB3_EOF

            let mut m: i64 = 0;
            if 0 < d {
                d -= 1;
                let t = b.advance(3).get3();
                if !(0 < t) { break; } // ERR_INVALID_VALUE; the first tryte can't be 0 or negative
                m = t as i64;

                while 0 < d {
                    d -= 1;
                    let t = b.advance(3).get3();
                    m *= 27;
                    m += t as i64;
                }

                if SIZE_MAX < m as usize { break; } // ERR_INVALID_VALUE
            }
            self.0 = m as usize;
            //TODO: check for truncation

            let end = b.dropped_size();
            return Some(b.pickup(end - begin));
        };

        None
    }
}

impl<TW> PB3<TW> for Trint3 where TW: TritWord + Copy {
    fn sizeof(&self) -> usize {
        3
    }
    fn encode(&self, b: &mut TritMutSlice<TW>) -> TritMutSlice<TW> {
        assert!(b.size() >= 3);
        b.advance(3).put3(self.0);
        b.pickup(3)
    }
    fn decode(&mut self, b: &mut TritConstSlice<TW>) -> Option<TritConstSlice<TW>>{
        if b.size() < 3 {
            None
        } else {
            self.0 = b.advance(3).get3();
            Some(b.pickup(3))
        }
    }
}
impl<TW> Absorb<TW> for Trint3 where TW: TritWord + Copy {}

impl<TW> PB3<TW> for Trint9 where TW: TritWord + Copy {
    fn sizeof(&self) -> usize {
        9
    }
    fn encode(&self, b: &mut TritMutSlice<TW>) -> TritMutSlice<TW> {
        assert!(b.size() >= 9);
        b.advance(9).put9(self.0);
        b.pickup(9)
    }
    fn decode(&mut self, b: &mut TritConstSlice<TW>) -> Option<TritConstSlice<TW>>{
        if b.size() < 9 {
            None
        } else {
            self.0 = b.advance(9).get9();
            Some(b.pickup(9))
        }
    }
}
impl<TW> Absorb<TW> for Trint9 where TW: TritWord + Copy {}

impl<TW> PB3<TW> for Trint18 where TW: TritWord + Copy {
    fn sizeof(&self) -> usize {
        18
    }
    fn encode(&self, b: &mut TritMutSlice<TW>) -> TritMutSlice<TW> {
        assert!(b.size() >= 18);
        b.advance(18).put18(self.0);
        b.pickup(18)
    }
    fn decode(&mut self, b: &mut TritConstSlice<TW>) -> Option<TritConstSlice<TW>>{
        if b.size() < 18 {
            None
        } else {
            self.0 = b.advance(18).get18();
            Some(b.pickup(18))
        }
    }
}
impl<TW> Absorb<TW> for Trint18 where TW: TritWord + Copy {}

impl<TW> PB3<TW> for Trits<TW> where TW: TritWord + Copy {
    fn sizeof(&self) -> usize {
        self.0.size()
    }
    fn encode(&self, b: &mut TritMutSlice<TW>) -> TritMutSlice<TW> {
        let n = self.0.size();
        assert!(n <= b.size());
        self.0.slice().copy(*b);
        *b = b.drop(n);
        b.pickup(n)
    }
    fn decode(&mut self, b: &mut TritConstSlice<TW>) -> Option<TritConstSlice<TW>>{
        let n = self.0.size();
        if b.size() < n {
            None
        } else {
            b.copy(self.0.mut_slice());
            *b = b.drop(n);
            Some(b.pickup(n))
        }
    }
}
impl<TW> Absorb<TW> for Trits<TW> where TW: TritWord + Copy {}
impl<TW> Squeeze<TW> for Trits<TW> where TW: TritWord + Copy {}
impl<TW> Crypt<TW> for Trits<TW> where TW: TritWord + Copy {}
