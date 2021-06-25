//! Pre-shared key is a secret symmetric key shared between two parties and is used for
//! (session) key exchange.

use crate::{
    crypto::hashes::{
        blake2b,
        Digest,
    },
    prelude::{
        generic_array::{
            typenum::{
                U16,
                U32,
            },
            GenericArray,
        },
        HashMap,
        Vec,
    },
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
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
pub type PskIds = [PskId];

/// Make a Psk from arbitrary bytes
pub fn new_psk<F: PRP>(bytes: &[u8]) -> Psk {
    let hash = blake2b::Blake2b256::digest(bytes);
    let mut ctx = Spongos::<F>::init();
    ctx.absorb(hash);
    ctx.commit();
    let mut id: Vec<u8> = vec![0; PSK_SIZE];
    ctx.squeeze(&mut id);
    GenericArray::clone_from_slice(&id)
}

/// Make a PskId from arbitrary bytes
pub fn new_pskid<F: PRP>(bytes: &[u8]) -> PskId {
    let hash = blake2b::Blake2b256::digest(bytes);
    let mut ctx = Spongos::<F>::init();
    ctx.absorb(hash);
    ctx.commit();
    let mut id: Vec<u8> = vec![0; PSKID_SIZE];
    ctx.squeeze(&mut id);
    GenericArray::clone_from_slice(&id)
}

/// Select only pre-shared keys with given identifiers.
pub fn filter_psks<'a>(psks: &'a Psks, psk_ids: &'_ PskIds) -> Vec<IPsk<'a>> {
    psk_ids
        .iter()
        .filter_map(|psk_id| psks.get_key_value(psk_id))
        .collect::<Vec<(&PskId, &Psk)>>()
}
