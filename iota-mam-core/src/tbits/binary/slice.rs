use crate::tbits::slice::*;
use super::*;

impl<'a, TW: 'a> TbitSliceT<'a, TW>
where
    TW: BitWord,
{
    pub fn get_bit(&self) -> Bit {
        assert!(!self.is_empty());
        unsafe { TW::get_tbit(self.r.d, self.p) }
    }
    pub fn get_byte(&self) -> Byte {
        assert!(8 <= self.size());
        TW::get_byte(self.r.d, self.p)
    }
}

impl<'a, TW: 'a> TbitSliceMutT<'a, TW>
where
    TW: BitWord,
{
    pub fn put_bit(&mut self, t: Bit) {
        assert!(!self.is_empty());
        unsafe { TW::put_tbit(self.r.d, self.p, t) }
    }
    pub fn put_byte(&mut self, t: Byte) {
        assert!(8 <= self.size());
        TW::put_byte(self.r.d, self.p, t)
    }
}
