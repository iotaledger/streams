use std::fmt;
use std::vec::Vec;

use super::mt::*;

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
                let h0 = self.node(d + 1, 2 * i + 0);
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
    fn next<G, M>(&mut self, _g: &G, _m: &M) -> bool
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        if self.skn < max_skn(self.height) {
            self.skn += 1;
        }

        if self.skn == max_skn(self.height) {
            self.nodes = Vec::new();
        }

        self.skn != max_skn(self.height)
    }

    fn root(&self) -> &H {
        self.node(0, 0)
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
        if skn == max_skn(height) && nodes.is_empty() {
        } else if skn < max_skn(height) && tree_size(height) == nodes.len() {
        } else {
            return None;
        }

        Some(Self {
            height,
            skn,
            nodes,
        })
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

    fn run_mt<H, G, M>(height: Height, g: &G, m: &M)
    where
        H: 'static + Clone + Eq + fmt::Debug,
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        let mut mt = MT::gen(g, m, height);

        let mut skn = 0;
        let mut done = false;
        loop {
            let (store_height, store_skn, store_nodes) = mt.store();
            let loaded = MT::load(store_height, store_skn, store_nodes);
            assert!(loaded.is_some() && loaded.unwrap() == mt);

            if done {
                break;
            }

            let apath = mt.apath();
            let h = g.gen_leaf(skn);
            let apk = apath.fold(m, &h);
            println!("d={}, skn={}", mt.height(), mt.skn());
            assert_eq!(apk, *mt.root());
            skn += 1;
            if !mt.next(g, m) {
                done = true;
            }
        }
        assert_eq!(skn, 1 << mt.height());
    }
    fn run<H, G, M>(max_height: Height, g: G, m: M)
    where
        H: 'static + Clone + Eq + fmt::Debug,
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        let mt0 = MT::gen(&g, &m, 0);
        let pk0 = mt0.root();
        assert_eq!(*pk0, g.gen_leaf(0));

        let mt2 = MT::gen(&g, &m, 2);
        let pk2 = mt2.root();
        assert_eq!(
            *pk2,
            m.merge_nodes(
                &m.merge_nodes(&g.gen_leaf(0), &g.gen_leaf(1)),
                &m.merge_nodes(&g.gen_leaf(2), &g.gen_leaf(3))
            )
        );

        for height in 0..=max_height {
            run_mt(height, &g, &m);
        }
    }

    #[test]
    fn commutative() {
        run(5, |idx| 1u64 << idx, |h0: &u64, h1: &u64| h0 | h1);
    }

    #[test]
    fn non_commutative() {
        run(5, |idx| 1u64 << idx, |h0: &u64, h1: &u64| (h0 * 3 + h1) ^ 11);
    }
}
