//! Pre-shared key is a secret symmetric key shared between two parties and is used for
//! (session) key exchange.

use std::collections::HashMap;
use std::hash;
use crate::tbits::{word::BasicTbitWord, TbitsT};

/// Size of pre-shared key identifier.
pub const PSKID_SIZE: usize = 81;

/// Size of pre-shared key.
pub const PSK_SIZE: usize = 243;

/// Type of pre-shared key identifiers: `tryte pskid[27]`.
//TODO: Introduce NTrytes type in core and make a newtype. Same for Psk, NtruPkid.
pub type PskIdT<TW> = TbitsT<TW>;

/// Type of pre-shared keys: `tryte pskid[81]`.
pub type PskT<TW> = TbitsT<TW>;

/// Container for pre-shared keys.
pub type PsksT<TW> = HashMap<PskIdT<TW>, PskT<TW>>;

/// Entry in a PSK container, just a convenience type synonym.
pub type IPskT<'a, TW> = (&'a PskIdT<TW>, &'a PskT<TW>);

/// Container (set) of pre-shared key identifiers.
pub type PskIdsT<TW> = Vec<PskIdT<TW>>;

/// Select only pre-shared keys with given identifiers.
pub fn filter_psks<'a, TW>(psks: &'a PsksT<TW>, pskids: &'_ PskIdsT<TW>) -> Vec<IPskT<'a, TW>>
where
    TW: BasicTbitWord,
    TW::Tbit: hash::Hash,
{
    pskids
        .iter()
        .filter_map(|pskid| psks.get_key_value(pskid))
        .collect::<Vec<(&PskIdT<TW>, &PskT<TW>)>>()
}
