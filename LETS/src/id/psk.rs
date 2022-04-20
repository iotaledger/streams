use core::convert::{TryFrom, TryInto};

// use crate::{
//     prelude::{
//         generic_array::{
//             typenum::{
//                 U16,
//                 U32,
//             },
//             GenericArray,
//         },
//         HashMap,
//         String,
//         Vec,
//     },
//     prng,
//     sponge::{
//         prp::PRP,
//         spongos::Spongos,
//     },
//     try_or,
//     wrapped_err,
//     Errors,
//     Result,
//     WrappedError,
// };
use anyhow::{
    Error,
    Result,
};
// use generic_array::{
//     typenum::{
//         Unsigned,
//         U16,
//         U32,
//     },
//     GenericArray,
// };

use spongos::{
    ddml::types::NBytes,
    Spongos,
    PRP,
};

/// Size of pre-shared key identifier.
// const PSKID_SIZE: usize = 16;
// type PskIdSize = U16;

/// Size of pre-shared key.
// const PSK_SIZE: usize = 32;
// type PskSize = U32;

// pub(crate) type PskId = GenericArray<u8, PskIdSize>;

// type Psk = GenericArray<u8, PskSize>;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Psk([u8; 32]);

impl Psk {
    // TODO: REMOVE
    // const SIZE: usize = 32;

    fn new<F, T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
        F: PRP,
    {
        let mut spongos = Spongos::<F>::init();
        spongos.absorb("PSK");
        spongos.sponge(seed)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn to_pskid<F>(&self) -> PskId
    where
        F: PRP,
    {
        let mut spongos = Spongos::<F>::init();
        spongos.absorb("PSKID");
        spongos.sponge(self)
    }
}

impl AsRef<[u8]> for Psk {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Psk {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for Psk {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(Psk(bytes.try_into()?))
    }
}


#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Debug)]
pub struct PskId([u8; 16]);

// TODO: REMOVE
// pub(crate) trait TypeSized {
//     type SizeType;
// }

// impl TypeSized for PskId {
//     type SizeType = U16;
// }

impl PskId {
    // TODO: REMOVE
    // const SIZE: usize = <Self as TypeSized>::SizeType::USIZE;
    // const SIZE: usize = 16;

    fn new<F, T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
        F: PRP,
    {
        Psk::new::<F, T>(seed).to_pskid::<F>()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for PskId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for PskId {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for PskId {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Ok(PskId(bytes.try_into()?))
    }
}

// TODO: REMOVE
// /// Entry in a PSK container, just a convenience type synonym.
// type IPsk<'a> = (&'a PskId, &'a Psk);
// /// Container for pre-shared keys.
// type Psks = HashMap<PskId, Psk>;
// /// Container (set) of pre-shared key identifiers.
// type PskIds = [PskId];

// TODO: REMOVE
// /// Derive a Psk from arbitrary secret seed bytes.
// fn psk_from_seed<F: PRP>(seed_bytes: &[u8]) -> Psk {
//     // TODO: WAIT FOR VLAD ANSWER
//     // Prng::<F>::from_seed(seed_bytes).gen("PSK")
//     Spongos::hash(seed_bytes)
// }

// /// Derive a PskId from existing Psk.
// fn pskid_from_psk<F: PRP>(psk: &Psk) -> PskId {
//     // TODO: WAIT FOR VLAD ANSWER
//     // Prng::<F>::from_seed(psk).gen("PSKID")
//     Spongos::hash(psk)
// }

// TODO: REMOVE
// /// Make a PskId from string or it's hash if the string is too long.
// fn pskid_from_str<F: PRP>(id: &str) -> PskId {
//     if id.as_bytes().len() < PSKID_SIZE {
//         let mut pskid = PskId::default();
//         pskid.as_mut_slice()[..id.as_bytes().len()].copy_from_slice(id.as_bytes());
//         pskid
//     } else {
//         // TODO: WAIT FOR VLAD ANSWER
//         Spongos::hash(id)
//         // let mut s = Spongos::<F>::init();
//         // s.absorb("PSKID");
//         // s.absorb(id.as_bytes());
//         // s.commit();
//         // s.squeeze_arr()
//     }
// }

// TODO: REMOVE
// /// Represent PskId bytes as hex string.
// fn pskid_to_hex_string(pskid: &PskId) -> String {
//     hex::encode(pskid)
// }

// TODO: Convert
// /// Create a PskId from hex string.
// fn pskid_from_hex_str(hex_str: &str) -> Result<PskId> {
//     let pskid_bytes =
//         hex::decode(hex_str).map_err(|e| wrapped_err!(Errors::BadHexFormat(hex_str.into()), WrappedError(e)))?;
//     try_or!(
//         PSKID_SIZE == pskid_bytes.len(),
//         Errors::LengthMismatch(PSKID_SIZE, pskid_bytes.len())
//     )?;
//     Ok(PskId::clone_from_slice(&pskid_bytes))
// }

// TODO: REMOVE
// /// Select only pre-shared keys with given identifiers.
// fn filter_psks<'a>(psks: &'a Psks, psk_ids: &'_ PskIds) -> Vec<IPsk<'a>> {
//     psk_ids
//         .iter()
//         .filter_map(|psk_id| psks.get_key_value(psk_id))
//         .collect::<Vec<IPsk>>()
// }
