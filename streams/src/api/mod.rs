use core::convert::{TryFrom, TryInto};

/// Identifier Key storage. Used for keeping track of channel state
mod key_store;

pub(crate) mod message;
mod messages;
pub(crate) mod send_response;
/// User Client
pub(crate) mod user;
pub(crate) mod user_builder;

/// The base branch constant for the start of a new channel. All branches require a topic for
/// address generation, and all new branches will be linked to the Announcement on the base branch
const BASE_BRANCH: lets::message::Topic = lets::message::Topic([0u8;32]);