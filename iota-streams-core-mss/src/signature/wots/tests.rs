use super::*;
use iota_streams_core::{
    prng::Prng,
    sponge::{
        prp::PRP,
        spongos::hash_data,
    },
    tbits::{
        word::{
            BasicTbitWord,
            IntTbitWord,
            SpongosTbitWord,
        },
        Tbits,
    },
};

pub fn sign_verify<TW, P, G>()
where
    TW: BasicTbitWord + SpongosTbitWord + IntTbitWord,
    P: Parameters<TW>,
    G: PRP<TW> + Default,
{
    let k = Tbits::<TW>::zero(Prng::<TW, G>::KEY_SIZE);
    let prng = Prng::<TW, G>::init(k);
    let n = Tbits::<TW>::zero(33);
    let sk = PrivateKey::<TW, P>::gen(&prng, &[n.slice()]);
    let pk = PublicKey::<TW, P>::gen(&sk);

    let x = Tbits::<TW>::zero(123);
    let mut h = Tbits::<TW>::zero(P::HASH_SIZE);
    let mut s = Tbits::<TW>::zero(P::SIGNATURE_SIZE);

    hash_data::<TW, G>(x.slice(), h.slice_mut());
    sk.sign(h.slice(), s.slice_mut());
    let r = pk.verify(h.slice(), s.slice());
    assert!(r, "WOTS verify failed");
    //TODO: modify h, s, pk
    /*
     */
}
