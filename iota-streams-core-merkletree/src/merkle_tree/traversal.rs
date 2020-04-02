use std::fmt;
use std::vec::Vec;

use super::*;

/// Merkle-tree node.
#[derive(Copy, Clone)]
struct Node<H> {
    /// Node level height, `0` -- leaf, `D` -- root.
    d: Height,
    /// Node index `0..2^d`.
    i: Idx,
    /// Associated hash-value.
    h: H,
}

impl<H> PartialEq for Node<H>
where
    H: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.d == other.d && self.i == other.i && self.h == other.h
    }
}
impl<H> Eq for Node<H> where H: Eq {}

impl<H> fmt::Debug for Node<H>
where
    H: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}:{}:{:?}>", self.d, self.i, self.h)
    }
}

#[derive(Clone)]
struct Stack<H> {
    /// Max stack size, max level of the top node.
    d: Height,
    /// Index of the top node, `0..2^d`.
    i: Idx,
    /// Stack itself.
    s: Vec<Node<H>>,
}

impl<H> Stack<H> {
    /// Create an empty stack for level `d`.
    fn new(d: Height) -> Self {
        Self {
            d,
            i: 0,
            s: Vec::new(),
        }
    }
    fn is_empty(&self) -> bool {
        self.s.is_empty()
    }
    fn len(&self) -> usize {
        self.s.len()
    }
    fn top(&self) -> &Node<H> {
        debug_assert!(!self.is_empty());
        &self.s[self.s.len() - 1]
    }
    fn before_top(&self) -> &Node<H> {
        debug_assert!(self.len() > 1);
        &self.s[self.s.len() - 2]
    }
    fn push(&mut self, n: Node<H>) {
        self.s.push(n)
    }
    fn pop(&mut self) -> Option<Node<H>> {
        self.s.pop()
    }

    fn is_finished(&self) -> bool {
        !self.is_empty() && self.top().d >= self.d
    }
    fn can_merge(&self) -> bool {
        self.len() > 1 && self.top().d == self.before_top().d
    }
    fn merge<M>(&mut self, m: &M)
    where
        M: MergeNodes<H>,
    {
        // Merge the top 2 nodes having the same height.
        if let Some(right_node) = self.pop() {
            if let Some(left_node) = self.pop() {
                // Same level?
                debug_assert_eq!(right_node.d, left_node.d);
                // Neighbours?
                debug_assert_eq!(1, left_node.i ^ right_node.i);
                debug_assert_eq!(1 + left_node.i, right_node.i);

                // Merge nodes into a new one on the upper level and with the corresponding index.
                let merged_node = Node {
                    d: left_node.d + 1,
                    i: left_node.i / 2,
                    h: m.merge_nodes(&left_node.h, &right_node.h),
                };
                self.push(merged_node);
            }
        }
    }
    fn can_add_leaf(&self, max_skn: Idx) -> bool {
        self.i < max_skn
    }
    fn add_leaf<G>(&mut self, g: &G)
    where
        G: GenLeaf<H>,
    {
        // Stack is not finished, gen and push the next leaf.
        let next_leaf = Node {
            d: 0,
            i: self.i,
            h: g.gen_leaf(self.i),
        };
        self.push(next_leaf);
        self.i += 1;
    }
    fn update<G, M>(&mut self, g: &G, m: &M, height: Height)
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        if self.is_finished() {
            // Finished, nothing to do.
        } else if self.can_merge() {
            self.merge(m);
        } else if self.can_add_leaf(max_skn(height)) {
            self.add_leaf(g);
        }
    }
}

impl<H> PartialEq for Stack<H>
where
    H: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.d == other.d && self.i == other.i && self.s == other.s
    }
}
impl<H> Eq for Stack<H> where H: Eq {}

impl<H> fmt::Debug for Stack<H>
where
    H: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{}:{}:{:?}}}", self.d, self.i, self.s)
    }
}

#[derive(Clone)]
pub struct MT<H> {
    height: Height,
    root: H,
    apath: APath<H>,
    stacks: Vec<Stack<H>>,
}

fn gen_mt<H, G, M>(g: &G, m: &M, height: Height) -> (H, APath<H>, Vec<Stack<H>>)
where
    H: Clone,
    G: GenLeaf<H>,
    M: MergeNodes<H>,
{
    let mut apath = APath::new(height);
    let mut stacks = Vec::with_capacity(height);

    // init stacks
    for d in 0..height {
        stacks.push(Stack::new(d));
    }

    if height == 0 {
        // Root is leaf.
        let root = g.gen_leaf(0);
        (root, apath, stacks)
    } else {
        // Traversal stack.
        let mut stack = Stack::new(height);

        loop {
            // One step.
            stack.update(g, m, height);
            let top = stack.top();

            if top.d == height {
                // Done, `top` is root.
                let root = top.h.clone();
                return (root, apath, stacks);
            }

            if top.i == 1 {
                debug_assert_eq!(top.d, apath.nodes.len());
                // Current apath note, add to `apath`.
                apath.push(top.h.clone());
            } else if top.i == 0 && top.d != height {
                // Push to stack `top.d`.
                stacks[top.d].push(top.clone());
            }
        }
    }
}

impl<H> MT<H> {
    fn refresh(&mut self) {
        let skn = self.apath.skn;
        for d in 0..self.height {
            let dd = 1 << d;
            if skn % dd != 0 {
                break;
            }

            // `skn` is the index of the left-most leaf in some sub-tree of height `d`.
            let stack = &mut self.stacks[d];
            // Corresponding stack must be finished.
            debug_assert_eq!(1, stack.len());
            if let Some(n) = stack.pop() {
                // Node `n` is the root of the previous sub-tree.
                debug_assert_eq!(d, n.d);
                // Put it as corresponding apath node.
                self.apath.nodes[d] = n.h;
            }

            stack.i = (skn + dd) ^ dd;
        }
    }

    fn build_stacks<G, M>(&mut self, g: &G, m: &M)
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        let height = self.height;
        for d in 0..height {
            let stack = &mut self.stacks[d];
            stack.update(g, m, height);
            stack.update(g, m, height);
        }
    }
}

impl<H> TraversableMerkleTree<H> for MT<H>
where
    H: Clone,
{
    fn gen<G, M>(g: &G, m: &M, height: Height) -> Self
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        let (root, apath, stacks) = gen_mt(g, m, height);
        let mt = Self {
            height,
            root,
            apath,
            stacks,
        };
        mt
    }

    fn next<G, M>(&mut self, g: &G, m: &M) -> bool
    where
        G: GenLeaf<H>,
        M: MergeNodes<H>,
    {
        if self.skn() < max_skn(self.height()) {
            self.apath.skn += 1;
        }

        if self.skn() == max_skn(self.height()) {
            // Cleanup apath and stacks.
            self.apath.nodes = Vec::new();
            self.stacks = Vec::new();
            false
        } else {
            self.refresh();
            self.build_stacks(g, m);
            true
        }
    }

    fn root(&self) -> &H {
        &self.root
    }

    fn height(&self) -> Height {
        self.height
    }

    fn skn(&self) -> Idx {
        self.apath.skn
    }

    fn apath(&self) -> APath<H> {
        self.apath.clone()
    }

    fn store(&self) -> (Height, Idx, Vec<H>) {
        let mut nodes = self.apath.nodes.clone();
        nodes.push(self.root.clone());

        for stack in self.stacks.iter() {
            for node in stack.s.iter() {
                nodes.push(node.h.clone());
            }
        }

        (self.height(), self.skn(), nodes)
    }

    fn load(height: Height, skn: Idx, nodes: Vec<H>) -> Option<Self> {
        if skn == max_skn(height) {
            if 1 != nodes.len() {
                return None;
            }

            let mut inode = nodes.into_iter();
            if let Some(root) = inode.next() {
                return Some(Self {
                    height,
                    root,
                    apath: APath {
                        skn,
                        nodes: Vec::new(),
                    },
                    stacks: Vec::new(),
                });
            } else {
                return None;
            }
        }

        if skn >= max_skn(height) || height > nodes.len() {
            return None;
        }

        let g = |_idx: Idx| ();
        let m = |_h0: &(), _h1: &()| ();
        let mut dummy_mt = MT::gen(&g, &m, height);
        for _ in 0..skn {
            dummy_mt.next(&g, &m);
        }

        let mut stacks_len = 0;
        for dummy_stack in dummy_mt.stacks.iter() {
            stacks_len += dummy_stack.len();
        }
        if nodes.len() != height + 1 + stacks_len {
            return None;
        }

        // Consuming iterator.
        let mut inode = nodes.into_iter();

        // Build apath first.
        let mut apath = Vec::with_capacity(height);
        for _ in 0..height {
            if let Some(h) = inode.next() {
                apath.push(h);
            }
        }

        // Get root.
        if let Some(root) = inode.next() {
            // Build stacks next.
            let mut stacks = Vec::with_capacity(height);
            for dummy_stack in dummy_mt.stacks.iter() {
                let mut s = Vec::new();

                for dummy_node in dummy_stack.s.iter() {
                    if let Some(h) = inode.next() {
                        let n = Node {
                            d: dummy_node.d,
                            i: dummy_node.i,
                            h,
                        };
                        s.push(n);
                    } else {
                        return None;
                    }
                }

                let stack = Stack {
                    d: dummy_stack.d,
                    i: dummy_stack.i,
                    s,
                };
                stacks.push(stack);
            }

            Some(Self {
                height,
                root,
                apath: APath { skn, nodes: apath },
                stacks,
            })
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
        self.height == other.height
            && self.root == other.root
            && self.apath == other.apath
            && self.stacks == other.stacks
    }
}
impl<H> Eq for MT<H> where H: Eq {}

impl<H> fmt::Debug for MT<H>
where
    H: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}:{}:{:?}>", self.height, self.apath.skn, self.stacks)
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
