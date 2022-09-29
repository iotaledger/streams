use crypto::keys::x25519;

use crate::{
    ddml::{
        commands::{sizeof::Context, X25519},
        types::NBytes,
    },
    error::Result,
};

impl<'a, T: AsRef<[u8]>> X25519<&'a x25519::PublicKey, NBytes<T>> for Context {
    fn x25519(&mut self, _pk: &x25519::PublicKey, encryption_key: NBytes<T>) -> Result<&mut Self> {
        self.size += x25519::PUBLIC_KEY_LENGTH + encryption_key.inner().as_ref().len();
        Ok(self)
    }
}
