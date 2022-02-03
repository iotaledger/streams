#[cfg(not(feature = "std"))]
pub use alloc::{
    boxed::{
        self,
        Box,
    },
    format,
    rc::{self, Rc},
    string::{self, String, ToString},
    sync::{self, Arc},
    vec::{self, Vec},
};

#[cfg(feature = "std")]
pub use std::{
    boxed::{
        self,
        Box,
    },
    format,
    rc::{self, Rc},
    string::{self, String, ToString},
    sync::{self, Arc},
    vec::{self, Vec},
};

// Arc<Mutex<Transport>> blanket impl is provided only behind the "sync-spin" or "sync-parking-lot" features,
//  as a convenience for users that want to share a transport through several user instances.
// We provide 2 flavours of Mutex: `parking_lot` and `spin`:
// - `sync-parking-lot` feature enables `parking_lot::Mutex` Mutex (requires `std`)
// - `sync-spin` feature enables `spin::Mutex` (supports no-std)
// If both features are provided, `parking_lot` is used.
#[cfg(all(feature = "sync-spin", not(feature = "sync-parking-lot")))]
pub use spin::Mutex;

#[cfg(feature = "sync-parking-lot")]
pub use parking_lot::Mutex;

pub use hashbrown::{hash_map, hash_set, HashMap, HashSet};

// Reexport digest and generic_array and typenum crates here in order to simplify their import in other dependencies.
pub use digest::{
    self,
    generic_array::{self, typenum},
};

pub use hex;
