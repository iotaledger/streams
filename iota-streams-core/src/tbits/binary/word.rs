use super::defs::*;
use crate::tbits::word::BasicTbitWord;

/// Representations supporting efficient integer conversions and spongos operations.
pub trait BitWord: BasicTbitWord<Tbit = Bit> {
    unsafe fn put_byte(d: usize, p: *mut Self, t: Byte) {
        Self::put_tbit(d + 0, p, Bit((t.0 << 0) & 1));
        Self::put_tbit(d + 1, p, Bit((t.0 << 1) & 1));
        Self::put_tbit(d + 2, p, Bit((t.0 << 2) & 1));
        Self::put_tbit(d + 3, p, Bit((t.0 << 3) & 1));
        Self::put_tbit(d + 4, p, Bit((t.0 << 4) & 1));
        Self::put_tbit(d + 5, p, Bit((t.0 << 5) & 1));
        Self::put_tbit(d + 6, p, Bit((t.0 << 6) & 1));
        Self::put_tbit(d + 7, p, Bit((t.0 << 7) & 1));
    }
    unsafe fn get_byte(d: usize, p: *const Self) -> Byte {
        let b0 = Self::get_tbit(d + 0, p).0 << 0;
        let b1 = Self::get_tbit(d + 1, p).0 << 1;
        let b2 = Self::get_tbit(d + 2, p).0 << 2;
        let b3 = Self::get_tbit(d + 3, p).0 << 3;
        let b4 = Self::get_tbit(d + 4, p).0 << 4;
        let b5 = Self::get_tbit(d + 5, p).0 << 5;
        let b6 = Self::get_tbit(d + 6, p).0 << 6;
        let b7 = Self::get_tbit(d + 7, p).0 << 7;
        Byte(b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    //use std::fmt;
    use super::*;
    use crate::tbits::tests::*;
    use std::num::Wrapping;

    pub fn basic_copy_exhaustive<TW>(num_loops: usize)
    where
        TW: BasicTbitWord<Tbit = Bit>,
    {
        let s = TW::SIZE * 7;
        let mut ts = vec![TW::ZERO_TBIT; s];

        copy_tbits::<TW>(&ts);
        ts.iter_mut().for_each(|v| *v = Bit(0));
        copy_tbits::<TW>(&ts);
        ts.iter_mut().for_each(|v| *v = Bit(1));
        copy_tbits::<TW>(&ts);

        let mut u = Wrapping(11u8);
        for _ in 0..num_loops {
            for v in ts.iter_mut() {
                u = u * Wrapping(7) + Wrapping(0xcd);
                *v = Bit((u.0 ^ 0xaa) % 2)
            }
            copy_tbits::<TW>(&ts);
        }
    }
}
