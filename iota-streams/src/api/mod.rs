/// Identifier Key storage. Used for keeping track of channel state
mod key_store;

pub(crate) mod message;
mod messages;
pub(crate) mod send_response;
/// User Client
pub(crate) mod user;
pub(crate) mod user_builder;

// #[cfg(all(feature = "duh"))]
// mod tangle;

// /// Derive a Psk from a secret seed
// fn psk_from_seed(seed_bytes: &[u8]) -> Psk {
//     psk::psk_from_seed::<DefaultF>(seed_bytes)
// }

// /// Derive a PskId from a secret seed
// fn pskid_from_psk(psk: &Psk) -> PskId {
//     psk::pskid_from_psk::<DefaultF>(psk)
// }

// /// Derive a PskId from a secret seed
// fn pskid_from_seed(seed_bytes: &[u8]) -> PskId {
//     psk::pskid_from_seed::<DefaultF>(seed_bytes)
// }

// /// Create a PskId from a string or it's hash if the string is too long
// fn pskid_from_str(id: &str) -> PskId {
//     psk::pskid_from_str::<DefaultF>(id)
// }

// TODO: REMOVE

// /// Identifier Key storage. Used for keeping track of channel state
// mod key_store;

// /// We would need an array import in prelude, and using IntoIter with size specifying...
// /// type_complexity to be determined in future issue

// /// Base level api for user implementation
// mod user;

// use user::User as ApiUser;

// /// Tangle-specific Channel API.
// #[cfg(all(feature = "tangle"))]
// mod tangle;

// use iota_streams_core::psk::{
//     self,
//     Psk,
//     PskId,
// };
// use iota_streams_core::sponge::prp::keccak::KeccakF1600;

// /// Default spongos PRP.
// type DefaultF = KeccakF1600;

// /// Derive a Psk from a secret seed
// fn psk_from_seed(seed_bytes: &[u8]) -> Psk {
//     psk::psk_from_seed::<DefaultF>(seed_bytes)
// }

// /// Derive a PskId from a secret seed
// fn pskid_from_psk(psk: &Psk) -> PskId {
//     psk::pskid_from_psk::<DefaultF>(psk)
// }

// /// Derive a PskId from a secret seed
// fn pskid_from_seed(seed_bytes: &[u8]) -> PskId {
//     psk::pskid_from_seed::<DefaultF>(seed_bytes)
// }

// /// Create a PskId from a string or it's hash if the string is too long
// fn pskid_from_str(id: &str) -> PskId {
//     psk::pskid_from_str::<DefaultF>(id)
// }

// use iota_streams_app::transport;

// /// Tangle Address Link type.
// type Address = transport::tangle::TangleAddress;
// /// Binary encoded message type.
// type Message = transport::tangle::TangleMessage;

// /// Test Transport.
// type BucketTransport = iota_streams_app::transport::BucketTransport<Address, Message>;

// /// Transportation trait for Tangle Client implementation
// // TODO: Use trait synonyms `Transport = transport::Transport<DefaultF, Address>;`.
// trait Transport: transport::Transport<Address, Message> + Clone + Default {}
// impl<T> Transport for T where T: transport::Transport<Address, Message> + Clone + Default {}

// use tangle::{
//     MessageContent,
//     UnwrappedMessage,
//     User,
//     UserBuilder,
// };
