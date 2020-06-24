//! Pre-shared key is a secret symmetric key shared between two parties and is used for
//! (session) key exchange.

use std::{
    collections::HashMap,
    hash,
};

/// Size of pre-shared key identifier.
pub const PSKID_SIZE: usize = 81;

/// Size of pre-shared key.
pub const PSK_SIZE: usize = 243;

/// Type of pre-shared key identifiers: `tryte pskid[27]`.
//TODO: Introduce NTrytes type in core and make a newtype. Same for Psk, NtruPkid.
pub type PskId = Vec<u8>;

/// Type of pre-shared keys: `tryte pskid[81]`.
pub type Psk = Vec<u8>;

/// Container for pre-shared keys.
pub type Psks = HashMap<PskId, Psk>;

/// Entry in a PSK container, just a convenience type synonym.
pub type IPsk<'a> = (&'a PskId, &'a Psk);

/// Container (set) of pre-shared key identifiers.
pub type PskIds = Vec<PskId>;

/// Select only pre-shared keys with given identifiers.
pub fn filter_psks<'a>(psks: &'a Psks, pskids: &'_ PskIds) -> Vec<IPsk<'a>>
{
    pskids
        .iter()
        .filter_map(|pskid| psks.get_key_value(pskid))
        .collect::<Vec<(&PskId, &Psk)>>()
}
