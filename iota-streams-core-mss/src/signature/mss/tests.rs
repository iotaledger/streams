use super::*;
use iota_streams_core::{
    prng::Prng,
    tbits::{
        word::{
            IntTbitWord,
            SpongosTbitWord,
        },
        Tbits,
    },
};

pub fn sign_verify<TW, P>()
where
    TW: SpongosTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    let k = Tbits::zero(Prng::<TW, P::PrngG>::KEY_SIZE);
    let prng = Prng::<TW, P::PrngG>::init(k);
    let n = Tbits::<TW>::zero(33);

    for d in 0..2 {
        let mut sk = PrivateKey::<TW, P>::gen(&prng, n.slice(), d);

        let h = Tbits::<TW>::zero(P::HASH_SIZE);
        let mut sig = Tbits::<TW>::zero(P::signature_size(d));
        loop {
            sk.sign(h.slice(), sig.slice_mut());
            sk.sign(h.slice(), sig.slice_mut());
            let ok = sk.public_key().verify(h.slice(), sig.slice());
            assert!(ok);
            if !sk.next() {
                break;
            }
        }
    }
}
