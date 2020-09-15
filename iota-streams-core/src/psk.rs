//! Pre-shared key is a secret symmetric key shared between two parties and is used for
//! (session) key exchange.

use crate::prelude::{
    HashMap,
    Vec,
    generic_array::{GenericArray, typenum::{U16, U32}},
};

/// Size of pre-shared key identifier.
pub const PSKID_SIZE: usize = 16;
pub type PskIdSize = U16;

/// Size of pre-shared key.
pub const PSK_SIZE: usize = 32;
pub type PskSize = U32;

/// Type of pre-shared key identifiers: `byte pskid[16]`.
// TODO: Introduce NBytes type in core and make a newtype. Same for Psk.
pub type PskId = GenericArray<u8, PskIdSize>;

/// Type of pre-shared keys: `byte psk[32]`.
pub type Psk = GenericArray<u8, PskSize>;

/// Entry in a PSK container, just a convenience type synonym.
pub type IPsk<'a> = (&'a PskId, &'a Psk);

/// Container for pre-shared keys.
pub type Psks = HashMap<PskId, Psk>;

/// Container (set) of pre-shared key identifiers.
pub type PskIds = Vec<PskId>;

/// Select only pre-shared keys with given identifiers.
pub fn filter_psks<'a>(psks: &'a Psks, psk_ids: &'_ PskIds) -> Vec<IPsk<'a>> {
    psk_ids
        .iter()
        .filter_map(|psk_id| psks.get_key_value(psk_id))
        .collect::<Vec<(&PskId, &Psk)>>()
}
