/// Identifier Key storage. Used for keeping track of channel state
mod key_store;

/// Base level api for user implementation
mod user;

// #[cfg(all(feature = "duh"))]
// mod tangle;

// /// Derive a Psk from a secret seed
// pub fn psk_from_seed(seed_bytes: &[u8]) -> Psk {
//     psk::psk_from_seed::<DefaultF>(seed_bytes)
// }

// /// Derive a PskId from a secret seed
// pub fn pskid_from_psk(psk: &Psk) -> PskId {
//     psk::pskid_from_psk::<DefaultF>(psk)
// }

// /// Derive a PskId from a secret seed
// pub fn pskid_from_seed(seed_bytes: &[u8]) -> PskId {
//     psk::pskid_from_seed::<DefaultF>(seed_bytes)
// }

// /// Create a PskId from a string or it's hash if the string is too long
// pub fn pskid_from_str(id: &str) -> PskId {
//     psk::pskid_from_str::<DefaultF>(id)
// }

// TODO: REMOVE