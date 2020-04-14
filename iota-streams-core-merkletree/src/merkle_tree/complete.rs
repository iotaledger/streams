use std::{
    fmt,
    vec::Vec,
};

use super::*;

#[derive(Clone)]
pub struct MT<H> {
    /// MT height.
    height: Height,

    /// Current skn.
    skn: Idx,

    /// Full binary tree linearized, leaves to root, left to right.
    nodes: Vec<H>,
}

impl<H> MT<H> {
    fn gen_mt<G, M>(&mut self, g: &G, m: &M)
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        // Gen leaves
        for i in 0..max_skn(self.height) {
            self.nodes.push(g.gen_leaf(i));
        }

        // Gen internal nodes
        for d in (0..self.height).rev() {
            for i in 0..max_skn(d) {
                let h0 = self.node(d + 1, 2 * i);
                let h1 = self.node(d + 1, 2 * i + 1);
                let h01 = m.merge_nodes(h0, h1);
                debug_assert_eq!(self.idx(d, i), self.nodes.len());
                self.nodes.push(h01);
            }
        }
    }

    fn idx(&self, d: Height, i: Idx) -> Idx {
        assert!(d <= self.height);
        assert!(i < max_skn(d));

        tree_size(self.height) - tree_size(d) + i
    }

    fn node(&self, d: Height, i: Idx) -> &H {
        &self.nodes[self.idx(d, i)]
    }
}

impl<H> TraversableMerkleTree<H> for MT<H>
where
    H: Clone,
{
    /// Generate Merkle tree, return root.
    fn gen<G, M>(g: &G, m: &M, height: Height) -> Self
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        let mut mt = Self {
            height,
            skn: 0,
            nodes: Vec::with_capacity(tree_size(height)),
        };
        mt.gen_mt(g, m);
        mt
    }

    /// Traverse MT to the next leaf.
    fn next<G, M>(&mut self, g: &G, _m: &M) -> bool
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        if self.skn < max_skn(self.height) {
            self.skn += 1;
        }

        if self.skn == max_skn(self.height) && self.height > 0 {
            // Leave root only.
            if let Some(root) = self.nodes.pop() {
                self.nodes[0] = root;
                self.nodes.resize_with(1, || g.gen_leaf(0));
                self.nodes.shrink_to_fit();
            }
        }

        self.skn != max_skn(self.height)
    }

    fn root(&self) -> &H {
        // Root is the last node, even in the exhausted tree.
        &self.nodes[self.nodes.len() - 1]
    }

    /// MT height.
    fn height(&self) -> Height {
        self.height
    }

    /// Current secret key (leaf) number.
    fn skn(&self) -> Idx {
        self.skn
    }

    /// Current apath (proof).
    fn apath(&self) -> APath<H> {
        let mut ap = APath::new(self.height);
        let mut i = self.skn;
        for d in (0..self.height).rev() {
            ap.push(self.node(d + 1, i ^ 1).clone());
            i /= 2;
        }
        ap.skn = self.skn;
        ap
    }

    fn store(&self) -> (Height, Idx, Vec<H>) {
        (self.height, self.skn, self.nodes.clone())
    }

    fn load(height: Height, skn: Idx, nodes: Vec<H>) -> Option<Self> {
        if (skn == max_skn(height) && nodes.len() == 1) || (skn < max_skn(height) && tree_size(height) == nodes.len()) {
            Some(Self { height, skn, nodes })
        } else {
            None
        }
    }
}

impl<H> PartialEq for MT<H>
where
    H: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.height == other.height && self.skn == other.skn && self.nodes == other.nodes
    }
}
impl<H> Eq for MT<H> where H: Eq {}

impl<H> fmt::Debug for MT<H>
where
    H: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}:{}:{:?}>", self.height, self.skn, self.nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_tree;

    #[test]
    fn commutative() {
        merkle_tree::tests::commutative::<MT<u64>>();
    }

    #[test]
    fn non_commutative() {
        merkle_tree::tests::non_commutative::<MT<u64>>();
    }
}
