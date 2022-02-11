pub use ed25519_dalek::{
    Keypair,
    PublicKey,
    SecretKey,
    Signature,
    PUBLIC_KEY_LENGTH,
    SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};

use core::hash::{
    Hash,
    Hasher,
};

pub type IPk<'a> = &'a PublicKey;

#[derive(Copy, Clone, Default, Eq, Debug)]
pub struct PublicKeyWrap(pub PublicKey);

// PartialEq implemented manually because Hash is implemented manually
impl PartialEq for PublicKeyWrap {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

// Hash implemented manually because ed25519_dalek::PublicKey does not implement Hash
impl Hash for PublicKeyWrap {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_bytes().hash(state)
    }
}

impl From<PublicKey> for PublicKeyWrap {
    fn from(pk: PublicKey) -> Self {
        Self(pk)
    }
}

impl<'a> From<&'a PublicKey> for &'a PublicKeyWrap {
    fn from(pk: &PublicKey) -> Self {
        // unsafe { core::mem::transmute(pk) }
        let ptr: *const PublicKey = pk;
        unsafe { &*(ptr as *const PublicKeyWrap) }
    }
}

impl<'a> From<&'a mut PublicKey> for &'a mut PublicKeyWrap {
    fn from(pk: &mut PublicKey) -> Self {
        // unsafe { core::mem::transmute(pk) }
        let ptr: *mut PublicKey = pk;
        unsafe { &mut *(ptr as *mut PublicKeyWrap) }
    }
}
