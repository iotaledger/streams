use crate::trits::Trits;

pub const PSKID_SIZE: usize = 81;
pub const PSK_SIZE: usize = 243;

pub type PskId = Trits; // tryte id[27]
pub type Psk = Trits; // tryte psk[81]
