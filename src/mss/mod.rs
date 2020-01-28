pub mod mss;
pub mod mt;
pub mod mtcomplete;
pub mod mttraversal;

use crate::trits::Trits;
pub use mss::*;

pub type PrivateKeyMTComplete = PrivateKeyT<mtcomplete::MT<Trits>>;
pub type PrivateKeyMTTraversal = PrivateKeyT<mttraversal::MT<Trits>>;
pub type PrivateKey = PrivateKeyMTComplete;
