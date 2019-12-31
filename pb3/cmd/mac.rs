//! Composite `MAC` operation essentially implements the following PB3 message:
//!
//! ```pb3
//! message MAC {
//!     commit;
//!     squeeze tryte tag[81];
//! }
//! ```
//!
//! # Fields
//!
//! * `tag` -- 81 trytes of authentication tag.

use crate::pb3::err::{Err, guard, Result};
use crate::spongos::{Spongos};
use crate::trits::{self, TritConstSlice, TritMutSlice, Trits};

/// MAC has fixed size.
pub fn sizeof_mac() -> usize {
    243
}

/// Commit and squeeze 81 trytes.
pub fn wrap_mac(s: &mut Spongos, b: &mut TritMutSlice) {
    let n = sizeof_mac();
    assert!(n <= b.size());
    s.commit();
    s.squeeze(b.advance(n));
}

/// Commit, squeeze 81 trytes and compare to the codeword.
pub fn unwrap_mac(s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
    let n = sizeof_mac();
    guard(n <= b.size(), Err::Eof)?;
    s.commit();
    let mut t = trits::Trits::zero(n);
    s.squeeze(t.mut_slice());
    guard(b.advance(n) == t.slice(), Err::MacVerifyFailed)
}
