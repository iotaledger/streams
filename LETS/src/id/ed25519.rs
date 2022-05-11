// Rust
use core::hash::Hash;

// 3rd-party

// IOTA
use crypto::signatures::ed25519;

// Streams
use spongos::{
    KeccakF1600,
    SpongosRng,
};

// Local

pub struct Ed25519(ed25519::SecretKey);

impl Ed25519 {
    pub fn new(secret: ed25519::SecretKey) -> Self {
        Self(secret)
    }

    pub fn from_seed<T>(seed: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self(ed25519::SecretKey::generate_with(&mut SpongosRng::<KeccakF1600>::new(
            seed,
        )))
    }

    pub(crate) fn inner(&self) -> &ed25519::SecretKey {
        &self.0
    }
}

impl PartialEq for Ed25519 {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for Ed25519 {}

impl PartialOrd for Ed25519 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ed25519 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.as_slice().cmp(other.0.as_slice())
    }
}

impl Hash for Ed25519 {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.as_slice().hash(state);
    }
}

impl AsRef<[u8]> for Ed25519 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<ed25519::SecretKey> for Ed25519 {
    fn from(secret_key: ed25519::SecretKey) -> Self {
        Self(secret_key)
    }
}
