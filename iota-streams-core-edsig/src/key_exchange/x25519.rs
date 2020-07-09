use std::collections::HashSet;
use std::hash;
use crate::signature::ed25519;

pub use x25519_dalek::{StaticSecret, PublicKey};
pub const PUBLIC_KEY_LENGTH: usize = 32;

pub struct PublicKeyWrap(pub PublicKey);

impl PartialEq for PublicKeyWrap {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().eq(other.0.as_bytes())
    }
}

impl Eq for PublicKeyWrap {}

impl hash::Hash for PublicKeyWrap {
    fn hash<H>(&self, state: &mut H) where H: hash::Hasher
    {
        self.0.as_bytes().hash(state)
    }
}

pub type Pks = HashSet<PublicKeyWrap>;
pub type IPk<'a> = &'a PublicKeyWrap;

pub fn filter_ke_pks<'a>(allowed_pks: &'a Pks, target_pks: &'a Vec<PublicKeyWrap>) -> Vec<IPk<'a>>
{
    target_pks
        .iter()
        .filter_map(|pk| allowed_pks.get(pk))
        .collect::<Vec<IPk<'a>>>()
}

pub fn keypair_from_ed25519(_kp: &ed25519::Keypair) -> (StaticSecret, PublicKey)
{
    panic!("not implemented")
}

pub fn public_from_ed25519(_pk: &ed25519::PublicKey) -> PublicKey
{
    panic!("not implemented")
}
