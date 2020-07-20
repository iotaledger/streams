//! Pre-shared key is a secret symmetric key shared between two parties and is used for
//! (session) key exchange.

use crate::prelude::{Vec, HashMap};

/// Size of pre-shared key identifier.
pub const PSKID_SIZE: usize = 16;

/// Size of pre-shared key.
pub const PSK_SIZE: usize = 32;

/// Type of pre-shared key identifiers: `byte pskid[16]`.
//TODO: Introduce NBytes type in core and make a newtype. Same for Psk.
pub type PskId = Vec<u8>;

/// Type of pre-shared keys: `byte psk[32]`.
pub type Psk = Vec<u8>;

/// Container for pre-shared keys.
pub type Psks = HashMap<PskId, Psk>;

/// Entry in a PSK container, just a convenience type synonym.
pub type IPsk<'a> = (&'a PskId, &'a Psk);

/// Container (set) of pre-shared key identifiers.
pub type PskIds = Vec<PskId>;

/// Select only pre-shared keys with given identifiers.
pub fn filter_psks<'a>(psks: &'a Psks, pskids: &'_ PskIds) -> Vec<IPsk<'a>> {
    pskids
        .iter()
        .filter_map(|pskid| psks.get_key_value(pskid))
        .collect::<Vec<(&PskId, &Psk)>>()
}
