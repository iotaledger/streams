//! NTRU key encapsulation `ntrukem(key)`.

use crate::ntru;
use crate::pb3::err::{Err, guard, Result};
use crate::prng::{PRNG};
use crate::spongos::{Spongos};
use crate::trits::{TritConstSlice, TritMutSlice};

pub fn sizeof_ntrukem() -> usize {
    ntru::EKEY_SIZE
}

pub fn wrap_ntrukem(key: TritConstSlice, pk: &ntru::PublicKey, prng: &PRNG, nonce: TritConstSlice, s: &mut Spongos, b: &mut TritMutSlice) {
    let n = sizeof_ntrukem();
    assert!(n <= b.size());
    assert!(key.size() == ntru::KEY_SIZE);
    pk.encr_with_s(s, prng, nonce, key, b.advance(n));
}

pub fn unwrap_ntrukem(key: TritMutSlice, sk: &ntru::PrivateKey, s: &mut Spongos, b: &mut TritConstSlice) -> Result<()> {
    assert!(key.size() == ntru::KEY_SIZE);
    let n = sizeof_ntrukem();
    guard(n <= b.size(), Err::Eof)?;
    guard(sk.decr_with_s(s, b.advance(n), key), Err::NtruDecrFailed)?;
    Ok(())
}
