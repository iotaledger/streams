use super::wrp::{Unwrap, Wrap};
use crate::pb3::err::{guard, Err, Result};
use crate::trits::{self, TritSlice, TritSliceMut};

/// `skip` helper.
struct WrapSkip;

impl Wrap for WrapSkip {
    /// Just encode tryte.
    fn wrap3(&mut self, b: &mut TritSliceMut, d: trits::Trint3) {
        let b0 = b.advance(3);
        b0.put3(d);
    }

    /// Just copy trits into the buffer `b`.
    fn wrapn(&mut self, b: &mut TritSliceMut, t: TritSlice) {
        t.copy(b.advance(t.size()));
    }
}

impl Unwrap for WrapSkip {
    /// Just decode tryte.
    fn unwrap3(&mut self, b: &mut TritSlice) -> Result<trits::Trint3> {
        guard(3 <= b.size(), Err::Eof)?;
        let b0 = b.advance(3);
        Ok(b0.get3())
    }

    /// Just copy trits from the buffer `b`.
    fn unwrapn(&mut self, b: &mut TritSlice, t: TritSliceMut) -> Result<()> {
        guard(t.size() <= b.size(), Err::Eof)?;
        b.advance(t.size()).copy(t);
        Ok(())
    }
}
