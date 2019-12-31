//! This module describes PB3 `repeated` modifier.

use super::size::{sizeof_sizet, Size};

/// `repeated` is encoded just like `size_t`
pub type Repeated = Size;

/// Constructor for `repeated`.
pub fn repeated(n: usize) -> Repeated {
    Size(n)
}

pub fn sizeof_repeated(n: usize) -> usize { sizeof_sizet(n) }
