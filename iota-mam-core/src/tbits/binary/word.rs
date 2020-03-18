use crate::tbits::word::BasicTbitWord;
use super::defs::*;

/// Representations supporting efficient integer conversions and spongos operations.
pub trait BitWord: BasicTbitWord<Tbit = Bit> {
    fn put_byte(d: usize, p: *mut Self, t: Byte) {
        unsafe {
            Self::put_tbit(d + 0, p, Bit((t.0 << 0) & 1));
            Self::put_tbit(d + 1, p, Bit((t.0 << 1) & 1));
            Self::put_tbit(d + 2, p, Bit((t.0 << 2) & 1));
            Self::put_tbit(d + 3, p, Bit((t.0 << 3) & 1));
            Self::put_tbit(d + 4, p, Bit((t.0 << 4) & 1));
            Self::put_tbit(d + 5, p, Bit((t.0 << 5) & 1));
            Self::put_tbit(d + 6, p, Bit((t.0 << 6) & 1));
            Self::put_tbit(d + 7, p, Bit((t.0 << 7) & 1));
        }
    }
    fn get_byte(d: usize, p: *const Self) -> Byte {
        unsafe {
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
}

