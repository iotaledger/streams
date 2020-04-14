//! Pre-shared key is a secret symmetric key shared between two parties and is used for
//! (session) key exchange.

use crate::tbits::{
    word::BasicTbitWord,
    Tbits,
};
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
pub type PskId<TW> = Tbits<TW>;

/// Type of pre-shared keys: `tryte pskid[81]`.
pub type Psk<TW> = Tbits<TW>;

/// Container for pre-shared keys.
pub type Psks<TW> = HashMap<PskId<TW>, Psk<TW>>;

/// Entry in a PSK container, just a convenience type synonym.
pub type IPsk<'a, TW> = (&'a PskId<TW>, &'a Psk<TW>);

/// Container (set) of pre-shared key identifiers.
pub type PskIds<TW> = Vec<PskId<TW>>;

/// Select only pre-shared keys with given identifiers.
pub fn filter_psks<'a, TW>(psks: &'a Psks<TW>, pskids: &'_ PskIds<TW>) -> Vec<IPsk<'a, TW>>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    pskids
        .iter()
        .filter_map(|pskid| psks.get_key_value(pskid))
        .collect::<Vec<(&PskId<TW>, &Psk<TW>)>>()
}
