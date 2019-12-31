use std::fmt;

use crate::prng::{PRNG};
use crate::spongos::{hash_datas, Spongos};
use crate::trits::{Trint18, Trint6, TritConstSlice, TritMutSlice, Trits};
use crate::wots;

/// MSS public key size.
pub const PK_SIZE: usize = 243;

/// Trits needed to encode tree height part of SKN.
const SKN_TREE_HEIGHT_SIZE: usize = 4;

/// Trits needed to encode key number part of SKN.
const SKN_KEY_NUMBER_SIZE: usize = 14;

/// Trits needed to encode `skn`: tree height and key number.
pub const SKN_SIZE: usize = SKN_TREE_HEIGHT_SIZE + SKN_KEY_NUMBER_SIZE;

/// MSS authentication path size of height `d`.
pub fn apath_size(d: usize) -> usize { wots::PK_SIZE * d }

/// MSS signature size with a tree of height `d`.
pub fn sig_size(d: usize) -> usize { SKN_SIZE + wots::SIG_SIZE + apath_size(d) }

/// MSS signed hash value size.
pub const HASH_SIZE: usize = wots::HASH_SIZE;

/// Max Merkle tree height.
const MAX_D: usize = 20;

/// Size of hash values stored in Merkle tree.
const MT_HASH_SIZE: usize = wots::PUBLIC_KEY_SIZE;

/// Max skn value +1.
const fn max_skn(d: usize) -> usize { 1 << d }

#[derive(Clone)]
pub struct PrivateKey {
    height: usize, // 0..20
    skn: usize, // 0..2^height-1
    prng: PRNG, //TODO: store ref instead of copy
    nonce: Trits,
    nodes: Vec<Trits>,
}

#[derive(PartialEq,Eq,Clone,Debug)]
pub struct PublicKey {
    pub(crate) pk: Trits,
}

impl PrivateKey {

    /// Generate `i`-th WOTS private key.
    fn gen_leaf_sk(&self, i: Trint18) -> wots::PrivateKey {
        let mut ni = Trits::zero(18);
        ni.mut_slice().put18(i);
        let nonces = [self.nonce.slice(), ni.slice()];
        wots::PrivateKey::gen(&self.prng, &nonces)
    }

    /// Generate `i`-th WOTS public key and discard private key.
    fn gen_leaf_pk(&mut self, i: Trint18) {
        let wsk = self.gen_leaf_sk(i);
        let wpk = self.node_mut_slice(self.height, i as Trint18);
        wsk.calc_pk(wpk);
    }

    /// Return const slice to `i`-th node at height `d` where `0 ≤ i < 2ᵈ`.
    /// The node at height `d = 0` is root.
    fn node_slice(&self, d: usize, i: Trint18) -> TritConstSlice {
        assert!(d <= self.height);
        assert!(0 <= i && (i as usize) < (1 << d));
        let idx = (1 << d) + (i as usize) - 1;
        self.nodes[idx].slice()
    }

    /// Return mut slice to i-th node at height d; 0<=i<(1<<d), d=0 -- root.
    fn node_mut_slice(&mut self, d: usize, i: Trint18) -> TritMutSlice {
        assert!(d <= self.height);
        assert!(0 <= i && (i as usize) < (1 << d));
        let idx = (1 << d) + (i as usize) - 1;
        self.nodes[idx].mut_slice()
    }

    /// Root slice -- public key.
    pub fn root(&self) -> TritConstSlice {
        self.node_slice(0, 0)
    }

    /// Return PublicKey object.
    pub fn public_key(&self) -> PublicKey {
        PublicKey{ pk: Trits::from_slice(self.root()) }
    }

    /// Generate MSS Merkle tree of height `d` with `prng` and a `nonce`.
    /// In order to generate a new Merkle tree with the same `prng` the `nonce`
    /// must be unique.
    pub fn gen(prng: &PRNG, d: usize, nonce: TritConstSlice) -> Self {
        let mut sk = Self {
            height: d,
            skn: 0,
            prng: prng.clone(),
            nonce: nonce.clone_trits(),
            nodes: vec![Trits::zero(wots::PK_SIZE); (1 << (d + 1)) - 1],
        };

        // Gen leaves
        {
            let n = 1 << d;
            for i in 0..n {
                sk.gen_leaf_pk(i as Trint18);
            }
        }

        // Gen internal nodes
        for e in (0..d).rev() {
            let n = 1 << e;
            for i in 0..n {
                let h0 = sk.node_slice(e+1, (2 * i + 0) as Trint18);
                let h1 = sk.node_slice(e+1, (2 * i + 1) as Trint18);
                let h = [h0, h1];
                let h01 = sk.node_mut_slice(e, i as Trint18);
                hash_datas(&h, h01);
            }
        }

        sk
    }

    /// Return Merkle tree height.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Current WOTS secret key number.
    pub fn skn(&self) ->usize {
        self.skn
    }

    /// Produce authentication path `apath` for `i`-th WOTS secret key.
    fn unfold_apath(&self, mut i: usize, mut apath: TritMutSlice) {
        assert!(apath.size() == apath_size(self.height));
        for d in (0..self.height).rev() {
            let ai = if 0 == i % 2 { i + 1 } else { i - 1 };
            let ni = self.node_slice(d + 1, ai as Trint18);
            ni.copy(apath.take(MT_HASH_SIZE));
            apath = apath.drop(MT_HASH_SIZE);
            i = i / 2;
        }
    }

    /// Encode MT height and the current WOTS key number into `skn` slice.
    /// It has format: `height(4) || skn(14)`.
    fn encode_skn(&self, skn: TritMutSlice) {
        assert_eq!(skn.size(), SKN_SIZE);
        encode_skn(self.height as Trint6, self.skn as Trint18, skn);
    }

    /// Sign `hash` with the current WOTS private key and put it into `wotsig` slice.
    /// The implementation generates WOTS private key on the spot.
    fn encode_wotsig(&self, hash: TritConstSlice, wotsig: TritMutSlice) {
        assert_eq!(hash.size(), HASH_SIZE);
        assert_eq!(wotsig.size(), wots::SIG_SIZE);
        // TODO: Combine WOTS sk and signature generation into one loop so it's faster and constant time.
        let wsk = self.gen_leaf_sk(self.skn as Trint18);
        wsk.sign(hash, wotsig);
    }

    /// Encode authentication path `apath` for the current WOTS secret key.
    fn encode_apath(&self, apath: TritMutSlice) {
        assert_eq!(apath.size(), apath_size(self.height));
        self.unfold_apath(self.skn, apath);
    }

    /// Sign hash.
    ///
    /// Signature has the following format:
    ///   `height(4) || skn(14) || wots(81*162) || apath(height*243)`
    ///
    /// Note, call `next` in order to switch to the next WOTS sk, otherwise the current sk is going to be reused!
    pub fn sign(&self, hash: TritConstSlice, mut sig: TritMutSlice) {
        assert!(sig.size() == sig_size(self.height));
        self.encode_skn(sig.advance(SKN_SIZE));
        self.encode_wotsig(hash, sig.advance(wots::SIG_SIZE));
        self.encode_apath(sig);
    }

    /// Switch to the next WOTS secret private key.
    pub fn next(&mut self) -> bool {
        if self.skn + 1 < max_skn(self.height) {
            self.skn += 1;
            true
        } else {
            false
        }
    }
}

impl PublicKey {

    /// Recover signer's public key from hash-value `hash` and signature slice `sig`.
    ///
    /// The size of the signature depends on MT height which is encoded in the first
    /// 4 trits of the `sig`. The expected signature size is calculated from it and checked
    /// against the actual size of `sig` slice.
    ///
    /// The function fails in case of incorrect sizes of `hash` and `sig` slices or when
    /// `sig` can't be parsed. In case of success the `PublicKey` object and the encoded
    /// size of signature is returned and `sig` slice is advanced.
    pub fn recover(hash: TritConstSlice, sig: TritConstSlice) -> Option<(Self, usize)> {
        let mut pk = Trits::zero(PK_SIZE);
        let n = recover(pk.mut_slice(), hash, sig)?;
        Some((PublicKey{ pk: pk }, n))
    }

    /// Recover public key from `hash` and `sig` and compare it to `self`.
    /// `sig` must not have any trailing trits as possible with `recover`.
    pub fn verify(&self, hash: TritConstSlice, sig: TritConstSlice) -> bool {
        verify(self.pk.slice(), hash, sig)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pk)
    }
}

/// Encode MT height & current WOTS secret key number.
fn encode_skn(height: Trint6, skn: Trint18, t: TritMutSlice) {
    assert!(t.size() == SKN_SIZE);
    let mut ts = Trits::zero(18);

    ts.mut_slice().put6(height);
    ts.slice().take(4).copy(t.take(4));

    ts.mut_slice().put18(skn);
    ts.slice().take(14).copy(t.drop(4));
}

/// Try parse MT height & current WOTS secret key number.
fn parse_skn(t: TritConstSlice) -> Option<(Trint6, Trint18)> {
    assert!(t.size() == SKN_SIZE);
    let mut ts = Trits::zero(18);

    t.take(4).copy(ts.mut_slice().take(4));
    let height = ts.slice().get6();

    t.drop(4).copy(ts.mut_slice().take(14));
    let skn = ts.slice().get18();

    if 0 <= height && 0 <= skn && (skn as usize) < max_skn(height as usize) {
        Some((height, skn))
    } else {
        None
    }
}

/// Hash authentication path `ap` with the initial hash value in `hpk` up to the root
/// and recover public key and put it into `hpk`. The auth path trajectory in Merkle tree
/// is determined by the WOTS key number `skn`.
fn fold_apath(mut skn: Trint18, mut ap: TritConstSlice, hpk: TritMutSlice) {
    assert!(0 <= skn);
    while !ap.is_empty() {
        let mut h: [TritConstSlice; 2] = [hpk.as_const(), hpk.as_const()];
        h[(skn % 2) as usize] = hpk.as_const();
        h[(1 - (skn % 2)) as usize] = ap.take(MT_HASH_SIZE);
        hash_datas(&h, hpk);

        ap = ap.drop(MT_HASH_SIZE);
        skn /= 2;
    }
}

/// Recover public key `apk` from `skn`, signed `hash` value, wots signature `wotsig` and MT `apath`.
fn recover_apk(height: Trint6, skn: Trint18, hash: TritConstSlice, wotsig: TritConstSlice, apath: TritConstSlice, apk: TritMutSlice) {
    assert_eq!(apk.size(), PK_SIZE);
    assert_eq!(hash.size(), HASH_SIZE);
    assert_eq!(wotsig.size(), wots::SIG_SIZE);
    assert_eq!(apath.size(), apath_size(height as usize));

    wots::recover(hash, wotsig, apk);
    fold_apath(skn, apath, apk);
}

/// Recover public key `apk` from signature buffer `sig` using signed `hash` value and return MSS signature size.
pub fn recover(apk: TritMutSlice, hash: TritConstSlice, mut sig: TritConstSlice) -> Option<usize> {
    assert_eq!(apk.size(), PK_SIZE);

    if SKN_SIZE <= sig.size() {
        let (d, skn) = parse_skn(sig.advance(SKN_SIZE))?;
        let n = apath_size(d as usize);
        if wots::SIG_SIZE + n <= sig.size() {
            let (wotsig, apath) = sig.split_at(wots::SIG_SIZE);
            recover_apk(d, skn, hash, wotsig, apath.take(n), apk);
            return Some(SKN_SIZE + wots::SIG_SIZE + n);
        }
    }

    None
}

/// Recover public key from `hash` and `sig` and compare it to `pk`.
/// `sig` must not have any trailing trits as possible with `recover`.
pub fn verify(pk: TritConstSlice, hash: TritConstSlice, sig: TritConstSlice) -> bool {
    assert_eq!(pk.size(), PK_SIZE);
    let mut apk = Trits::zero(PK_SIZE);
    if let Some(sig_size) = recover(apk.mut_slice(), hash, sig) {
        sig.size() == sig_size && apk.slice() == pk
    } else {
        false
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sign_verify_d2() {
        let k = Trits::zero(crate::prng::KEY_SIZE);
        let prng = PRNG::init(k.slice());
        let n = Trits::zero(33);

        for d in 0..2 {
            let mut sk = PrivateKey::gen(&prng, d, n.slice());
            let pk = sk.root();

            let h = Trits::zero(HASH_SIZE);
            let mut sig = Trits::zero(sig_size(d));
            loop {
                sk.sign(h.slice(), sig.mut_slice());
                let ok = verify(pk, h.slice(), sig.slice());
                assert!(ok);
                if !sk.next() {
                    break;
                }
            }
        }
    }
}
