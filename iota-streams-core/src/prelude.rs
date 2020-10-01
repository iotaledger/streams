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
    rc::{
        self,
        Rc,
    }
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
    rc::{
        self,
        Rc,
    }
};

pub use hashbrown::{
    hash_map,
    hash_set,
    HashMap,
    HashSet,
};

// Reexport digest and generic_array and typenum crates here in order to simplify their import in other dependencies.
pub use digest::{
    self,
    generic_array::{
        self,
        typenum,
    },
};
