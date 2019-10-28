use crate::trits::*;
use crate::spongos::*;
use crate::prng::*;
use crate::wots as wots;

/// MSS public key size.
pub const PK_SIZE: usize = 243;

/// Trits needed to encode tree height part of SKN.
const SKN_TREE_HEIGHT_SIZE: usize = 4;

/// Trits needed to encode key number part of SKN.
const SKN_KEY_NUMBER_SIZE: usize = 14;

/// Trits needed to encode `skn`: tree height and key number.
const SKN_SIZE: usize = SKN_TREE_HEIGHT_SIZE + SKN_KEY_NUMBER_SIZE;

/// MSS authentication path size of height `d`.
fn apath_size(d: usize) -> usize { wots::PK_SIZE * d }

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

pub struct PrivateKey<TW> {
    height: usize, // 0..20
    skn: usize, // 0..2^height-1
    prng: PRNG<TW>, //TODO: store ref instead of copy
    nonce: Trits<TW>,
    nodes: Vec<Trits<TW>>,
}

impl<TW> PrivateKey<TW> where TW: TritWord + Copy {
    /// Generate i-th WOTS private key.
    fn gen_leaf_sk(&self, i: Trint18) -> wots::PrivateKey<TW> {
        let mut ni = Trits::<TW>::zero(18);
        ni.mut_slice().put18(i);
        let nonces = [self.nonce.slice(), ni.slice()];
        wots::PrivateKey::<TW>::gen(&self.prng, &nonces)
    }
    /// Generate i-th WOTS public key and discard private key.
    fn gen_leaf_pk(&mut self, i: Trint18) {
        let wsk = self.gen_leaf_sk(i);
        let wpk = self.node_mut_slice(self.height, i as Trint18);
        wsk.calc_pk(wpk);
    }
    /// Return const slice to i-th node at height d; 0<=i<(1<<d), d=0 -- root.
    fn node_slice(&self, d: usize, i: Trint18) -> TritConstSlice<TW> {
        assert!(d <= self.height);
        assert!(0 <= i && (i as usize) < (1 << d));
        let idx = (1 << d) + (i as usize) - 1;
        self.nodes[idx].slice()
    }
    /// Return mut slice to i-th node at height d; 0<=i<(1<<d), d=0 -- root.
    fn node_mut_slice(&mut self, d: usize, i: Trint18) -> TritMutSlice<TW> {
        assert!(d <= self.height);
        assert!(0 <= i && (i as usize) < (1 << d));
        let idx = (1 << d) + (i as usize) - 1;
        self.nodes[idx].mut_slice()
    }
    /// Root slice -- public key.
    pub fn root(&self) -> TritConstSlice<TW> {
        self.node_slice(0, 0)
    }

    /// Generate MSS Merkle tree of height d with prng and a unique nonce.
    pub fn gen(prng: &PRNG<TW>, d: usize, nonce: TritConstSlice<TW>) -> Self {
        let mut sk = Self {
            height: d,
            skn: 0,
            prng: prng.clone(),
            nonce: nonce.clone_trits(),
            nodes: vec![Trits::<TW>::zero(wots::PK_SIZE); (1 << (d + 1)) - 1],
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

    /// MT height
    pub fn height(&self) -> usize {
        self.height
    }
    /// Current WOTS secret key number
    pub fn skn(&self) ->usize {
        self.skn
    }
    fn apath(&self, mut i: usize, mut apath: TritMutSlice<TW>) {
        assert!(apath.size() == apath_size(self.height));
        for d in (0..self.height).rev() {
            let ai = if 0 == i % 2 { i + 1 } else { i - 1 };
            let ni = self.node_slice(d, ai as Trint18);
            ni.copy(apath.take(MT_HASH_SIZE));
            apath = apath.drop(MT_HASH_SIZE);
            i = i / 2;
        }
    }
    /// Sign hash.
    /// Signature has the following format:
    ///   height(4) || skn(14) || wots(81*162) || apath(height*243)
    /// Note, call `next` in order to go to the next WOTS sk, otherwise the current sk is going to be reused!
    pub fn sign(&self, hash: TritConstSlice<TW>, mut sig: TritMutSlice<TW>) {
        assert!(hash.size() == HASH_SIZE);
        assert!(sig.size() == sig_size(self.height));

        encode_skn(self.height as Trint6, self.skn as Trint18, sig.take(SKN_SIZE));
        sig = sig.drop(SKN_SIZE);

        {
            let wsk = self.gen_leaf_sk(self.skn as Trint18);
            wsk.sign(hash, sig.take(wots::SIG_SIZE));
        }
        sig = sig.drop(wots::SIG_SIZE);

        self.apath(self.skn, sig);
    }
    /// Switch to the next WOTS secret private key.
    pub fn next(&mut self) -> bool {
        if self.skn + 1 < max_skn(self.height) {
            false
        } else {
            self.skn += 1;
            true
        }
    }
}

/// Encode MT height & current WOTS secret key number.
fn encode_skn<TW>(height: Trint6, skn: Trint18, t: TritMutSlice<TW>) where TW: TritWord + Copy {
    assert!(t.size() == SKN_SIZE);
    let mut ts = Trits::<TW>::zero(18);

    ts.mut_slice().put6(height);
    ts.slice().take(4).copy(t.take(4));

    ts.mut_slice().put18(skn);
    ts.slice().take(14).copy(t.drop(4));
}
/// Try parse MT height & current WOTS secret key number.
fn parse_skn<TW>(t: TritConstSlice<TW>) -> Option<(Trint6, Trint18)> where TW: TritWord + Copy {
    assert!(t.size() == 18);
    let mut ts = Trits::<TW>::zero(18);

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

fn fold_apath<TW>(mut skn: Trint18, mut ap: TritConstSlice<TW>, hpk: TritMutSlice<TW>) where TW: TritWord + Copy {
    assert!(0 <= skn);
    while !ap.is_empty() {
        let mut h: [TritConstSlice<TW>; 2] = [hpk.as_const(), hpk.as_const()];
        h[(skn % 2) as usize] = hpk.as_const();
        h[(1 - (skn % 2)) as usize] = ap.take(MT_HASH_SIZE);
        hash_datas(&h, hpk);

        ap = ap.drop(MT_HASH_SIZE);
        skn /= 2;
    }
}

pub fn verify<TW>(pk: TritConstSlice<TW>, hash: TritConstSlice<TW>, mut sig: TritConstSlice<TW>) -> bool where TW: TritWord + Copy {
    assert!(pk.size() == PK_SIZE);
    assert!(hash.size() == HASH_SIZE);

    if sig.size() < 18 {return false; }
    let mut d: Trint6 = 0;
    let mut skn: Trint18 = 0;
    if let Some((d, skn)) = parse_skn(sig.take(18)) {
        sig = sig.drop(18);

        if sig.size() == sig_size(d as usize) - SKN_SIZE {
            let mut apk = Trits::<TW>::zero(PK_SIZE);
            wots::recover(hash, sig.take(wots::SIG_SIZE), apk.mut_slice());
            sig = sig.drop(wots::SIG_SIZE);
            fold_apath(skn, sig, apk.mut_slice());
            apk.slice() == pk
        } else {
            false
        }
    } else {
        false
    }
}

#[cfg(test)]
mod test_mss {
    use super::*;

    #[test]
    fn test_mss() {
        let k = Trits::<Trit>::zero(MAM_PRNG_SECRET_KEY_SIZE);
        let prng = PRNG::<Trit>::init(k.slice());
        let n = Trits::<Trit>::zero(33);

        let d: usize = 0;
        let sk = PrivateKey::<Trit>::gen(&prng, d, n.slice());
        let pk = sk.root();

        let mut h = Trits::<Trit>::zero(HASH_SIZE);
        let mut sig = Trits::<Trit>::zero(sig_size(d));
        sk.sign(h.slice(), sig.mut_slice());
        let ok = verify(pk, h.slice(), sig.slice());
        assert!(ok);
    }
}
