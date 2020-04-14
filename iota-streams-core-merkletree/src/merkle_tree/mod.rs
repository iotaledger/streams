use std::{
    borrow::Borrow,
    fmt,
    rc::Rc,
};

/// Type of tree heights.
pub type Height = usize;

/// Type of leaf/node indices within a tree level `d`: `0..max_skn(d)`.
pub type Idx = usize;

/// Secret key (leaf) count in a full binary tree of height `d`.
pub fn max_skn(d: Height) -> Idx {
    1 << d
}

/// Size of full binary tree of height `d`.
pub fn tree_size(d: Height) -> Idx {
    (1 << (d + 1)) - 1
}

/// Function that generates i-th leaf of the Merkle tree. Usually it captures a secret
/// (prng key and nonce).
pub trait GenLeaf<H> {
    fn gen_leaf(&self, idx: Idx) -> H;
}

/// Default implementations for functions and lambdas.
impl<H, T> GenLeaf<H> for T
where
    T: Fn(Idx) -> H,
{
    fn gen_leaf(&self, idx: Idx) -> H {
        self(idx)
    }
}

/// Function that merges two hash values of the Merkle tree. Usually it's a pure
/// function and doesn't capture any state.
pub trait MergeNodes<H> {
    fn merge_nodes(&self, h0: &H, h1: &H) -> H;
}

/// `GenLeaf` object can be shared via `Rc`.
impl<H, T> GenLeaf<H> for Rc<T>
where
    T: GenLeaf<H>,
{
    fn gen_leaf(&self, idx: Idx) -> H {
        GenLeaf::gen_leaf(Borrow::<T>::borrow(self), idx)
    }
}

/// Default implementations for functions and lambdas.
impl<H, T> MergeNodes<H> for T
where
    T: Fn(&H, &H) -> H,
{
    fn merge_nodes(&self, h0: &H, h1: &H) -> H {
        self(h0, h1)
    }
}

/// `MergeNodes` object can be shared via `Rc`.
impl<H, T> MergeNodes<H> for Rc<T>
where
    T: MergeNodes<H>,
{
    fn merge_nodes(&self, h0: &H, h1: &H) -> H {
        MergeNodes::merge_nodes(Borrow::<T>::borrow(self), h0, h1)
    }
}

/// Authentication path, also called proof.
#[derive(Clone)]
pub struct APath<H> {
    /// Secret key number.
    pub(crate) skn: Idx,

    /// Hash values leaf to root (not including root).
    pub(crate) nodes: Vec<H>,
}

impl<H> APath<H> {
    /// Create an empty apath for height `d`.
    pub fn new(d: Height) -> Self {
        Self {
            skn: 0,
            nodes: Vec::with_capacity(d),
        }
    }

    /// Secret key (leaf) number associated to `self` apath.
    pub fn skn(&self) -> Idx {
        self.skn
    }

    /// Fold apath by merging nodes from leaf to root, resulting `h` value is the root.
    ///
    /// `MergeNodes` argument is arguably a part of `APath` type. It's passed as an
    /// argument to `fold_mut` in order to simplify the implementation.
    pub fn fold_mut<M>(&self, m: &M, h: &mut H) -> bool
    where
        M: MergeNodes<H>,
    {
        let mut skn = self.skn;
        for n in self.nodes.iter() {
            if skn % 2 == 0 {
                *h = m.merge_nodes(h, n);
            } else {
                *h = m.merge_nodes(n, h);
            }
            skn /= 2;
        }
        // `skn` must be consumed completely otherwise apath is too short.
        skn == 0
    }

    pub fn nodes(&self) -> &Vec<H> {
        &self.nodes
    }

    /// Add a node to the `self` apath at the next level starting from leaf.
    pub fn push(&mut self, h: H) {
        self.nodes.push(h);
    }
}

impl<H> APath<H>
where
    H: Clone,
{
    /// Fold apath by merging nodes from leaf to root, returning the root.
    pub fn fold<M>(&self, m: &M, h: &H) -> H
    where
        M: MergeNodes<H>,
    {
        let mut hh = h.clone();
        let done = self.fold_mut(m, &mut hh);
        debug_assert!(done);
        hh
    }
}

impl<H> PartialEq for APath<H>
where
    H: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.skn == other.skn && self.nodes == other.nodes
    }
}

impl<H> Eq for APath<H> where H: Eq {}

impl<H> fmt::Debug for APath<H>
where
    H: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "APath({}, {:?})", self.skn, self.nodes)
    }
}

/// Merkle tree for which the authentication paths are requested in order of corresponding leaves.
/// Efficient implementations allow for more compact representation compared to a complete tree.
pub trait TraversableMerkleTree<H>
where
    Self: Sized,
{
    /// Generate Merkle tree.
    fn gen<G, M>(g: &G, m: &M, height: Height) -> Self
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>;

    /// Traverse MT to the next leaf.
    /// Once all the tree has been traversed, it frees allocated memory.
    fn next<G, M>(&mut self, g: &G, m: &M) -> bool
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>;

    /// MT root.
    fn root(&self) -> &H;

    /// MT height.
    fn height(&self) -> Height;

    /// Current secret key (leaf) number.
    fn skn(&self) -> Idx;

    /// Current apath (proof).
    fn apath(&self) -> APath<H>;

    /// Serialize as tuple.
    fn store(&self) -> (Height, Idx, Vec<H>);

    /// Try deserialize from tuple.
    fn load(height: Height, skn: Idx, nodes: Vec<H>) -> Option<Self>;
}

pub mod complete;
pub mod tests;
pub mod traversal;
