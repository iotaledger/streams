#[cfg(not(feature = "std"))]
pub use alloc::{
    string::{
        self,
        String,
        ToString,
    },
    vec::{
        self,
        Vec,
    },
};

#[cfg(feature = "std")]
pub use std::{
    string::{
        self,
        String,
        ToString,
    },
    vec::{
        self,
        Vec,
    },
};

// Stub for tests & examples
#[cfg(not(feature = "std"))]
#[macro_export]
macro_rules! println {
    () => {};
    ($($arg:tt)*) => {};
}

#[cfg(feature = "std")]
#[macro_export]
pub use std::println;

pub use hashbrown::{
    hash_map,
    hash_set,
    HashMap,
    HashSet,
};
