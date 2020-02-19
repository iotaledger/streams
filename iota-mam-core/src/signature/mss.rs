use std::fmt;

use crate::prng::PRNG;
use crate::spongos::{hash_datas, Spongos};
use crate::trits::{Trint18, Trint6, TritSlice, TritSliceMut, Trits};

use super::merkle_tree::{self, *};
use super::wots;

/// MSS public key size.
pub const PK_SIZE: usize = 243;

/// Trits needed to encode tree height part of SKN.
const SKN_TREE_HEIGHT_SIZE: usize = 4;

/// Trits needed to encode key number part of SKN.
const SKN_KEY_NUMBER_SIZE: usize = 14;

/// Trits needed to encode `skn`: tree height and key number.
pub const SKN_SIZE: usize = SKN_TREE_HEIGHT_SIZE + SKN_KEY_NUMBER_SIZE;

/// MSS authentication path size of height `d`.
pub fn apath_size(d: usize) -> usize {
    wots::PK_SIZE * d
}

/// MSS signature size with a tree of height `d`.
pub fn sig_size(d: usize) -> usize {
    SKN_SIZE + wots::SIG_SIZE + apath_size(d)
}

/// MSS signed hash value size.
pub const HASH_SIZE: usize = wots::HASH_SIZE;

/// Max Merkle tree height.
const MAX_D: usize = 20;

/// Size of hash values stored in Merkle tree.
const MT_HASH_SIZE: usize = wots::PUBLIC_KEY_SIZE;

/// Max skn value +1.
const fn max_idx(d: usize) -> usize {
    1 << d
}

#[derive(Clone)]
struct SK {
    prng: PRNG,
    nonce: Trits,
}

impl SK {
    /// Generate `i`-th WOTS private key.
    fn gen_leaf_sk(&self, i: Trint18) -> wots::PrivateKey {
        let mut ni = Trits::zero(18);
        ni.slice_mut().put18(i);
        let nonces = [self.nonce.slice(), ni.slice()];
        wots::PrivateKey::gen(&self.prng, &nonces)
    }

    /// Generate `i`-th WOTS public key and discard private key.
    fn gen_leaf_pk(&self, i: Idx) -> Trits {
        let wsk = self.gen_leaf_sk(Trint18(i as i32));
        let mut wpk = Trits::zero(PK_SIZE);
        wsk.calc_pk(wpk.slice_mut());
        wpk
    }
}

impl GenLeaf<Trits> for SK {
    fn gen_leaf(&self, i: Idx) -> Trits {
        self.gen_leaf_pk(i)
    }
}

#[derive(Clone)]
pub struct PrivateKeyT<MT> {
    sk: SK,
    mt: MT,
}

pub type PrivateKeyMTComplete = PrivateKeyT<merkle_tree::complete::MT<Trits>>;
pub type PrivateKeyMTTraversal = PrivateKeyT<merkle_tree::traversal::MT<Trits>>;

#[cfg(not(mss_merkle_tree_traversal))]
pub type PrivateKey = PrivateKeyMTComplete;

#[cfg(mss_merkle_tree_traversal)]
pub type PrivateKey = PrivateKeyMTTraversal;

fn merge_nodes(h0: &Trits, h1: &Trits) -> Trits {
    debug_assert_eq!(PK_SIZE, h0.size());
    debug_assert_eq!(PK_SIZE, h1.size());

    let mut s = Spongos::init();
    s.absorb_trits(h0);
    s.absorb_trits(h1);
    s.commit();
    s.squeeze_trits(PK_SIZE)
}

impl<MT> PrivateKeyT<MT>
where
    MT: merkle_tree::TraversableMerkleTree<Trits>,
{
    /// Generate MSS Merkle tree of height `d` with `prng` and a `nonce`.
    /// In order to generate a new Merkle tree with the same `prng` the `nonce`
    /// must be unique.
    pub fn gen(prng: &PRNG, nonce: TritSlice, height: usize) -> Self {
        assert!(height <= MAX_D);
        let sk = SK {
            prng: prng.clone(),
            nonce: nonce.clone_trits(),
        };
        let mt = MT::gen(&sk, &merge_nodes, height);
        Self { sk, mt }
    }

    pub fn public_key<'a>(&'a self) -> &'a PublicKey {
        unsafe { std::mem::transmute::<&'a Trits, &'a PublicKey>(self.mt.root()) }
    }

    pub fn nonce(&self) -> &Trits {
        &self.sk.nonce
    }

    /// Return Merkle tree height.
    pub fn height(&self) -> usize {
        self.mt.height()
    }

    /// Current WOTS secret key number.
    pub fn skn(&self) -> usize {
        self.mt.skn()
    }

    /// Encode MT height and the current WOTS key number into `skn` slice.
    /// It has format: `height(4) || skn(14)`.
    fn encode_skn(&self, skn: TritSliceMut) {
        assert_eq!(SKN_SIZE, skn.size());
        encode_skn(
            Trint6(self.height() as i16),
            Trint18(self.skn() as i32),
            skn,
        );
    }

    /// Sign `hash` with the current WOTS private key and put it into `wotsig` slice.
    /// The implementation generates WOTS private key on the spot.
    fn encode_wotsig(&self, hash: TritSlice, wotsig: TritSliceMut) {
        assert_eq!(HASH_SIZE, hash.size());
        assert_eq!(wots::SIG_SIZE, wotsig.size());
        let wsk = self.sk.gen_leaf_sk(Trint18(self.skn() as i32));
        wsk.sign(hash, wotsig);
    }

    /// Encode authentication path `apath` for the current WOTS secret key.
    fn encode_apath(&self, mut apath: TritSliceMut) {
        assert_eq!(apath_size(self.height()), apath.size());
        let ap = self.mt.apath();
        debug_assert_eq!(self.height(), ap.nodes.len());
        for n in ap.nodes.iter() {
            n.slice().copy(apath.take(MT_HASH_SIZE));
            apath = apath.drop(MT_HASH_SIZE);
        }
    }

    /// Sign hash.
    ///
    /// Signature has the following format:
    ///   `height(4) || skn(14) || wots(81*162) || apath(height*243)`
    ///
    /// Note, call `next` in order to switch to the next WOTS sk, otherwise the current sk is going to be reused!
    pub fn sign(&self, hash: TritSlice, mut sig: TritSliceMut) {
        assert!(self.private_keys_left() > 0);
        assert_eq!(sig.size(), sig_size(self.height()));
        self.encode_skn(sig.advance(SKN_SIZE));
        self.encode_wotsig(hash, sig.advance(wots::SIG_SIZE));
        self.encode_apath(sig);
    }

    /// The number of WOTS secret private key left.
    pub fn private_keys_left(&self) -> usize {
        max_idx(self.height()) - self.mt.skn()
    }

    /// Switch to the next WOTS secret private key.
    /// Once all WOTS private keys are exhausted, the inner Merkle tree is cleared.
    pub fn next(&mut self) -> bool {
        self.mt.next(&self.sk, &merge_nodes)
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PublicKey {
    pub(crate) pk: Trits,
}

impl PublicKey {
    pub fn trits(&self) -> &Trits {
        &self.pk
    }

    pub fn trits_mut(&mut self) -> &mut Trits {
        &mut self.pk
    }
}

/// Default implementation for PublicKey, may be useful when public key is recovered.
impl Default for PublicKey {
    fn default() -> Self {
        Self {
            pk: Trits::zero(PK_SIZE),
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
    pub fn recover(hash: TritSlice, sig: TritSlice) -> Option<(Self, usize)> {
        let mut pk = Trits::zero(PK_SIZE);
        let n = recover(pk.slice_mut(), hash, sig)?;
        Some((PublicKey { pk }, n))
    }

    /// Recover public key from `hash` and `sig` and compare it to `self`.
    /// `sig` must not have any trailing trits as possible with `recover`.
    pub fn verify(&self, hash: TritSlice, sig: TritSlice) -> bool {
        verify(self.pk.slice(), hash, sig)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pk)
    }
}

/// Encode MT height & current WOTS secret key number.
fn encode_skn(height: Trint6, skn: Trint18, t: TritSliceMut) {
    assert!(t.size() == SKN_SIZE);
    let mut ts = Trits::zero(18);

    ts.slice_mut().put6(height);
    ts.slice().take(4).copy(t.take(4));

    ts.slice_mut().put18(skn);
    ts.slice().take(14).copy(t.drop(4));
}

/// Try parse MT height & current WOTS secret key number.
pub fn parse_skn(t: TritSlice) -> Option<(Trint6, Trint18)> {
    assert!(t.size() == SKN_SIZE);
    let mut ts = Trits::zero(18);

    t.take(4).copy(ts.slice_mut().take(4));
    let height = ts.slice().get6();

    t.drop(4).copy(ts.slice_mut().take(14));
    let skn = ts.slice().get18();

    if Trint6(0) <= dbg!(height)
        && Trint18(0) <= dbg!(skn)
        && (skn.0 as usize) < max_idx(height.0 as usize)
    {
        Some((height, skn))
    } else {
        None
    }
}

/// Hash authentication path `ap` with the initial hash value in `hpk` up to the root
/// and recover public key and put it into `hpk`. The auth path trajectory in Merkle tree
/// is determined by the WOTS key number `skn`.
fn fold_apath(i: Trint18, mut ap: TritSlice, hpk: TritSliceMut) {
    let mut skn = i.0;
    assert!(0 <= skn);
    while !ap.is_empty() {
        let mut h: [TritSlice; 2] = [hpk.as_const(), hpk.as_const()];
        h[(skn % 2) as usize] = hpk.as_const();
        h[(1 - (skn % 2)) as usize] = ap.take(MT_HASH_SIZE);
        hash_datas(&h, hpk);

        ap = ap.drop(MT_HASH_SIZE);
        skn /= 2;
    }
}

/// Recover public key `apk` from `skn`, signed `hash` value, wots signature `wotsig` and MT `apath`.
pub fn recover_apk(
    height: Trint6,
    skn: Trint18,
    hash: TritSlice,
    wotsig: TritSlice,
    apath: TritSlice,
    apk: TritSliceMut,
) {
    assert_eq!(apk.size(), PK_SIZE);
    assert_eq!(hash.size(), HASH_SIZE);
    assert_eq!(wotsig.size(), wots::SIG_SIZE);
    assert!(Trint6(0) <= height);
    assert_eq!(apath.size(), apath_size(height.0 as usize));

    wots::recover(hash, wotsig, apk);
    fold_apath(skn, apath, apk);
}

/// Recover public key `apk` from signature buffer `sig` using signed `hash` value and return MSS signature size.
pub fn recover(apk: TritSliceMut, hash: TritSlice, mut sig: TritSlice) -> Option<usize> {
    assert_eq!(apk.size(), PK_SIZE);

    if SKN_SIZE <= sig.size() {
        let (d, skn) = parse_skn(sig.advance(SKN_SIZE))?;
        let n = apath_size(d.0 as usize);
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
pub fn verify(pk: TritSlice, hash: TritSlice, sig: TritSlice) -> bool {
    assert_eq!(PK_SIZE, pk.size());
    let mut apk = Trits::zero(PK_SIZE);
    if let Some(sig_size) = recover(apk.slice_mut(), hash, sig) {
        sig.size() == sig_size && apk.slice() == pk
    } else {
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn sign_verify_mt<MT>()
    where
        MT: TraversableMerkleTree<Trits>,
    {
        let k = Trits::zero(crate::prng::KEY_SIZE);
        let prng = PRNG::init(k.slice());
        let n = Trits::zero(33);

        for d in 0..2 {
            let mut sk = PrivateKeyT::<MT>::gen(&prng, n.slice(), d);

            let h = Trits::zero(HASH_SIZE);
            let mut sig = Trits::zero(sig_size(d));
            loop {
                sk.sign(h.slice(), sig.slice_mut());
                let ok = sk.public_key().verify(h.slice(), sig.slice());
                assert!(ok);
                if !sk.next() {
                    break;
                }
            }
        }
    }

    #[test]
    fn sign_verify_d2_mtcomplete() {
        sign_verify_mt::<complete::MT<Trits>>();
    }

    #[test]
    fn sign_verify_d2_mttraversal() {
        sign_verify_mt::<traversal::MT<Trits>>();
    }
}
