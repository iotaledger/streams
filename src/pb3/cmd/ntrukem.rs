//! NTRU key encapsulation `ntrukem(key)`.

use crate::ntru;
use crate::pb3::err::{guard, Err, Result};
use crate::prng::PRNG;
use crate::spongos::Spongos;
use crate::trits::{TritSlice, TritSliceMut};

pub fn sizeof_ntrukem() -> usize {
    ntru::EKEY_SIZE
}

pub fn wrap_ntrukem(
    key: TritSlice,
    pk: &ntru::PublicKey,
    prng: &PRNG,
    nonce: TritSlice,
    s: &mut Spongos,
    b: &mut TritSliceMut,
) {
    let n = sizeof_ntrukem();
    assert!(n <= b.size());
    assert!(key.size() == ntru::KEY_SIZE);
    pk.encr_with_s(s, prng, nonce, key, b.advance(n));
}

pub fn unwrap_ntrukem(
    key: TritSliceMut,
    sk: &ntru::PrivateKey,
    s: &mut Spongos,
    b: &mut TritSlice,
) -> Result<()> {
    assert!(key.size() == ntru::KEY_SIZE);
    let n = sizeof_ntrukem();
    guard(n <= b.size(), Err::Eof)?;
    guard(sk.decr_with_s(s, b.advance(n), key), Err::NtruDecrFailed)?;
    Ok(())
}
