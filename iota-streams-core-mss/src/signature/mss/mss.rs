use iota_streams_core::{
    hash::Hash,
    prng::Prng,
    sponge::prp::PRP,
    tbits::{
        word::{BasicTbitWord, IntTbitWord, SpongosTbitWord},
        TbitSlice, TbitSliceMut, Tbits,
    },
};

use crate::signature::wots::{self, Parameters as _};
use iota_streams_core_merkletree::merkle_tree::*;

pub trait Parameters<TW> {
    type PrngG: PRP<TW> + Clone + Default;

    type WotsParameters: wots::Parameters<TW>;

    /// MSS public key size.
    const PUBLIC_KEY_SIZE: usize = Self::WotsParameters::PUBLIC_KEY_SIZE; //243;

    /// Tbits needed to encode tree height part of SKN.
    const SKN_TREE_HEIGHT_SIZE: usize; // = 4;

    /// Tbits needed to encode key number part of SKN.
    const SKN_KEY_NUMBER_SIZE: usize; // = 14;

    /// Tbits needed to encode `skn`: tree height and key number.
    const SKN_SIZE: usize = Self::SKN_TREE_HEIGHT_SIZE + Self::SKN_KEY_NUMBER_SIZE;

    type MerkleTree: TraversableMerkleTree<Tbits<TW>>;

    /// MSS signed hash value size.
    const HASH_SIZE: usize = Self::WotsParameters::HASH_SIZE;

    /// Max Merkle tree height.
    const MAX_D: usize = 20;

    /// Size of hash values stored in Merkle tree.
    const MT_HASH_SIZE: usize = Self::WotsParameters::PUBLIC_KEY_SIZE;

    /// MSS authentication path size of height `d`.
    fn apath_size(d: usize) -> usize {
        Self::WotsParameters::PUBLIC_KEY_SIZE * d
    }

    /// MSS signature size with a tree of height `d`.
    fn signature_size(d: usize) -> usize {
        Self::SKN_SIZE + Self::WotsParameters::SIGNATURE_SIZE + Self::apath_size(d)
    }
}

/// Max skn value +1.
const fn max_idx(d: usize) -> usize {
    1 << d
}

fn merge_nodes<TW, P>(h0: TbitSlice<TW>, h1: TbitSlice<TW>, mut h: TbitSliceMut<TW>)
where
    TW: BasicTbitWord, //SpongosTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    debug_assert_eq!(P::PUBLIC_KEY_SIZE, h0.size());
    debug_assert_eq!(P::PUBLIC_KEY_SIZE, h1.size());

    let mut s = <<P as Parameters<TW>>::WotsParameters as wots::Parameters<TW>>::J::init();
    s.update(h0);
    s.update(h1);
    s.done(&mut h)
    /*
       let mut s = Spongos::init();
       s.absorb_tbits(h0);
       s.absorb_tbits(h1);
       s.commit();
       s.squeeze_tbits(PK_SIZE)
    */
}

fn merge_nodes_tbits<TW, P>(h0: &Tbits<TW>, h1: &Tbits<TW>) -> Tbits<TW>
where
    TW: BasicTbitWord, //SpongosTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    let mut h = Tbits::<TW>::zero(
        <<P as Parameters<TW>>::WotsParameters as wots::Parameters<TW>>::J::HASH_SIZE,
    );
    merge_nodes::<TW, P>(h0.slice(), h1.slice(), h.slice_mut());
    h
}

#[derive(Clone)]
struct SK<TW, P>
where
    P: Parameters<TW>,
{
    prng: Prng<TW, P::PrngG>,
    nonce: Tbits<TW>,
    _phantom: std::marker::PhantomData<P>,
}

impl<TW, P> SK<TW, P>
where
    TW: SpongosTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    /// Generate `i`-th WOTS private key.
    fn gen_leaf_sk(&self, i: usize) -> wots::PrivateKey<TW, P::WotsParameters> {
        let mut ni = Tbits::zero(P::SKN_KEY_NUMBER_SIZE);
        ni.slice_mut().put_usize(i);
        let nonces = [self.nonce.slice(), ni.slice()];
        wots::PrivateKey::<TW, P::WotsParameters>::gen(&self.prng, &nonces)
    }

    /// Generate `i`-th WOTS public key and discard private key.
    fn gen_leaf_pk(&self, i: usize) -> Tbits<TW> {
        let wsk = self.gen_leaf_sk(i);
        let mut wpk = Tbits::zero(P::PUBLIC_KEY_SIZE);
        wsk.calc_pk(wpk.slice_mut());
        wpk
    }
}

impl<TW, P> GenLeaf<Tbits<TW>> for SK<TW, P>
where
    TW: SpongosTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    fn gen_leaf(&self, i: usize) -> Tbits<TW> {
        self.gen_leaf_pk(i)
    }
}

#[derive(Clone)]
pub struct PrivateKey<TW, P>
where
    P: Parameters<TW>,
{
    sk: SK<TW, P>,
    mt: P::MerkleTree,
}

//pub type PrivateKeyMTComplete = PrivateKey<merkle_tree::complete::MT<Tbits>>;
//pub type PrivateKeyMTTraversal = PrivateKey<merkle_tree::traversal::MT<Tbits>>;

//#[cfg(not(mss_merkle_tree_traversal))]
//pub type PrivateKey = PrivateKeyMTComplete;

//#[cfg(mss_merkle_tree_traversal)]
//pub type PrivateKey = PrivateKeyMTTraversal;

impl<TW, P> PrivateKey<TW, P>
where
    TW: SpongosTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    /// Generate MSS Merkle tree of height `d` with `prng` and a `nonce`.
    /// In order to generate a new Merkle tree with the same `prng` the `nonce`
    /// must be unique.
    pub fn gen(prng: &Prng<TW, P::PrngG>, nonce: TbitSlice<TW>, height: usize) -> Self {
        assert!(height <= P::MAX_D);
        let sk = SK {
            prng: prng.clone(),
            nonce: Tbits::<TW>::from_slice(nonce),
            _phantom: std::marker::PhantomData,
        };
        let mt = P::MerkleTree::gen(&sk, &merge_nodes_tbits::<TW, P>, height);
        Self { sk, mt }
    }

    pub fn public_key<'a>(&'a self) -> &'a PublicKey<TW, P> {
        unsafe { std::mem::transmute::<&'a Tbits<TW>, &'a PublicKey<TW, P>>(self.mt.root()) }
    }

    pub fn nonce(&self) -> &Tbits<TW> {
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
    fn encode_skn(&self, skn: TbitSliceMut<TW>) {
        assert_eq!(P::SKN_SIZE, skn.size());
        encode_skn::<TW, P>(self.height(), self.skn(), skn);
    }

    /// Sign `hash` with the current WOTS private key and put it into `wotsig` slice.
    /// The implementation generates WOTS private key on the spot.
    fn encode_wotsig(&self, hash: TbitSlice<TW>, wotsig: TbitSliceMut<TW>) {
        assert_eq!(P::HASH_SIZE, hash.size());
        assert_eq!(P::WotsParameters::SIGNATURE_SIZE, wotsig.size());
        let wsk = self.sk.gen_leaf_sk(self.skn());
        wsk.sign(hash, wotsig);
    }

    /// Encode authentication path `apath` for the current WOTS secret key.
    fn encode_apath(&self, mut apath: TbitSliceMut<TW>) {
        assert_eq!(P::apath_size(self.height()), apath.size());
        let ap = self.mt.apath();
        debug_assert_eq!(self.height(), ap.nodes().len());
        for n in ap.nodes().iter() {
            n.slice().copy(&apath.advance(P::MT_HASH_SIZE));
        }
    }

    /// Sign hash.
    ///
    /// Signature has the following format:
    ///   `height(4) || skn(14) || wots(81*162) || apath(height*243)`
    ///
    /// Note, call `next` in order to switch to the next WOTS sk, otherwise the current sk is going to be reused!
    pub fn sign(&self, hash: TbitSlice<TW>, mut sig: TbitSliceMut<TW>) {
        assert!(self.private_keys_left() > 0);
        assert_eq!(P::signature_size(self.height()), sig.size());
        self.encode_skn(sig.advance(P::SKN_SIZE));
        self.encode_wotsig(hash, sig.advance(P::WotsParameters::SIGNATURE_SIZE));
        self.encode_apath(sig);
    }

    pub fn sign_tbits(&self, hash: &Tbits<TW>) -> Tbits<TW> {
        let mut sig = Tbits::<TW>::zero(P::signature_size(self.height()));
        self.sign(hash.slice(), sig.slice_mut());
        sig
    }

    /// The number of WOTS secret private key left.
    pub fn private_keys_left(&self) -> usize {
        max_idx(self.height()) - self.mt.skn()
    }

    /// Switch to the next WOTS secret private key.
    /// Once all WOTS private keys are exhausted, the inner Merkle tree is cleared.
    pub fn next(&mut self) -> bool {
        self.mt.next(&self.sk, &merge_nodes_tbits::<TW, P>)
    }
}

//TODO: Debug
pub struct PublicKey<TW, P> {
    pub(crate) pk: Tbits<TW>,
    _phantom: std::marker::PhantomData<P>,
}

impl<TW, P> Clone for PublicKey<TW, P>
where
    TW: BasicTbitWord,
{
    fn clone(&self) -> Self {
        Self {
            pk: self.pk.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TW, P> PartialEq for PublicKey<TW, P>
where
    TW: BasicTbitWord,
{
    fn eq(&self, other: &Self) -> bool {
        self.pk == other.pk
    }
}
impl<TW, P> Eq for PublicKey<TW, P> where TW: BasicTbitWord {}

impl<TW, P> PublicKey<TW, P> {
    pub fn tbits(&self) -> &Tbits<TW> {
        &self.pk
    }

    pub fn tbits_mut(&mut self) -> &mut Tbits<TW> {
        &mut self.pk
    }
}

/// Default implementation for PublicKey, may be useful when public key is recovered.
impl<TW, P> Default for PublicKey<TW, P>
where
    TW: BasicTbitWord,
    P: Parameters<TW>,
{
    fn default() -> Self {
        Self {
            pk: Tbits::<TW>::zero(P::PUBLIC_KEY_SIZE),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<TW, P> PublicKey<TW, P>
where
    TW: BasicTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    /// Recover signer's public key from hash-value `hash` and signature slice `sig`.
    ///
    /// The size of the signature depends on MT height which is encoded in the first
    /// 4 tbits of the `sig`. The expected signature size is calculated from it and checked
    /// against the actual size of `sig` slice.
    ///
    /// The function fails in case of incorrect sizes of `hash` and `sig` slices or when
    /// `sig` can't be parsed. In case of success the `PublicKey` object and the encoded
    /// size of signature is returned and `sig` slice is advanced.
    pub fn recover(hash: TbitSlice<TW>, sig: TbitSlice<TW>) -> Option<(Self, usize)> {
        let mut pk = Tbits::<TW>::zero(P::PUBLIC_KEY_SIZE);
        let n = recover::<TW, P>(pk.slice_mut(), hash, sig)?;
        Some((
            PublicKey {
                pk,
                _phantom: std::marker::PhantomData,
            },
            n,
        ))
    }

    /// Recover public key from `hash` and `sig` and compare it to `self`.
    /// `sig` must not have any trailing tbits as possible with `recover`.
    pub fn verify(&self, hash: TbitSlice<TW>, sig: TbitSlice<TW>) -> bool {
        verify::<TW, P>(self.pk.slice(), hash, sig)
    }

    pub fn verify_tbits(&self, hash: &Tbits<TW>, sig: &Tbits<TW>) -> bool {
        self.verify(hash.slice(), sig.slice())
    }
}

/* TODO: ToString vs Display
impl<TW, P> fmt::Display for PublicKey<TW, P> where
    TW: StringTbitWord,
    TW::Tbit: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.pk)
    }
}
 */

/// Encode MT height & current WOTS secret key number.
fn encode_skn<TW, P>(height: usize, skn: usize, mut t: TbitSliceMut<TW>)
where
    TW: IntTbitWord,
    P: Parameters<TW>,
{
    assert!(t.size() == P::SKN_SIZE);
    t.advance(P::SKN_TREE_HEIGHT_SIZE).put_usize(height);
    t.advance(P::SKN_KEY_NUMBER_SIZE).put_usize(skn);
}

/// Try parse MT height & current WOTS secret key number.
pub fn parse_skn<TW, P>(mut t: TbitSlice<TW>) -> Option<(usize, usize)>
where
    TW: IntTbitWord,
    P: Parameters<TW>,
{
    assert!(t.size() == P::SKN_SIZE);
    let height = t.advance(P::SKN_TREE_HEIGHT_SIZE).get_usize();
    let skn = t.advance(P::SKN_KEY_NUMBER_SIZE).get_usize();
    if skn < max_idx(height) {
        Some((height, skn))
    } else {
        None
    }
}

/// Hash authentication path `ap` with the initial hash value in `hpk` up to the root
/// and recover public key and put it into `hpk`. The auth path trajectory in Merkle tree
/// is determined by the WOTS key number `skn`.
fn fold_apath<TW, P>(i: usize, mut ap: TbitSlice<TW>, hpk: TbitSliceMut<TW>)
where
    TW: BasicTbitWord,
    P: Parameters<TW>,
{
    unsafe {
        let mut skn = i;
        //assert!(0 <= skn);
        while !ap.is_empty() {
            let mut h: [TbitSlice<TW>; 2] = [hpk.as_const(), hpk.as_const()];
            h[(skn % 2) as usize] = hpk.as_const();
            h[(1 - (skn % 2)) as usize] = ap.advance(P::MT_HASH_SIZE);
            merge_nodes::<TW, P>(h[0], h[1], hpk.clone());

            skn /= 2;
        }
    }
}

/// Recover public key `apk` from `skn`, signed `hash` value, wots signature `wotsig` and MT `apath`.
pub fn recover_apk<TW, P>(
    height: usize,
    skn: usize,
    hash: TbitSlice<TW>,
    wotsig: TbitSlice<TW>,
    apath: TbitSlice<TW>,
    apk: TbitSliceMut<TW>,
) where
    TW: BasicTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    assert_eq!(apk.size(), P::PUBLIC_KEY_SIZE);
    assert_eq!(hash.size(), P::HASH_SIZE);
    assert_eq!(wotsig.size(), P::WotsParameters::SIGNATURE_SIZE);
    assert_eq!(apath.size(), P::apath_size(height));

    wots::recover::<TW, P::WotsParameters>(hash, wotsig, unsafe { apk.clone() });
    fold_apath::<TW, P>(skn, apath, apk);
}

/// Recover public key `apk` from signature buffer `sig` using signed `hash` value and return MSS signature size.
pub fn recover<TW, P>(
    apk: TbitSliceMut<TW>,
    hash: TbitSlice<TW>,
    mut sig: TbitSlice<TW>,
) -> Option<usize>
where
    TW: BasicTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    assert_eq!(apk.size(), P::PUBLIC_KEY_SIZE);

    if P::SKN_SIZE <= sig.size() {
        let (d, skn) = parse_skn::<TW, P>(sig.advance(P::SKN_SIZE))?;
        let n = P::apath_size(d);
        if P::WotsParameters::SIGNATURE_SIZE + n <= sig.size() {
            let (wotsig, apath) = sig.split_at(P::WotsParameters::SIGNATURE_SIZE);
            recover_apk::<TW, P>(d, skn, hash, wotsig, apath.take(n), apk);
            return Some(P::SKN_SIZE + P::WotsParameters::SIGNATURE_SIZE + n);
        }
    }

    None
}

/// Recover public key from `hash` and `sig` and compare it to `pk`.
/// `sig` must not have any trailing tbits as possible with `recover`.
pub fn verify<TW, P>(pk: TbitSlice<TW>, hash: TbitSlice<TW>, sig: TbitSlice<TW>) -> bool
where
    TW: BasicTbitWord + IntTbitWord,
    P: Parameters<TW>,
{
    assert_eq!(P::PUBLIC_KEY_SIZE, pk.size());
    let mut apk = Tbits::<TW>::zero(P::PUBLIC_KEY_SIZE);
    if let Some(sig_size) = recover::<TW, P>(apk.slice_mut(), hash, sig) {
        sig.size() == sig_size && apk.slice() == pk
    } else {
        false
    }
}
