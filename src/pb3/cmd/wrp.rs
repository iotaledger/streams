use crate::pb3::err::Result;
use crate::trits::{self, TritSlice, TritSliceMut};

/// Helper trait to wrap types that can be absorbed, encrypted or skipped.
pub trait Wrap {
    /// Wrap a tryte.
    fn wrap3(&mut self, b: &mut TritSliceMut, t: trits::Trint3);

    /// Wrap trits.
    fn wrapn(&mut self, b: &mut TritSliceMut, t: TritSlice);
}

/// Helper trait to unwrap types that can be absorbed, decrypted or skipped.
pub trait Unwrap {
    /// Unwrap a tryte.
    fn unwrap3(&mut self, b: &mut TritSlice) -> Result<trits::Trint3>;

    /// Unwrap trits.
    fn unwrapn(&mut self, b: &mut TritSlice, t: TritSliceMut) -> Result<()>;
}
