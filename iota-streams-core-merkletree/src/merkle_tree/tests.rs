use super::*;

fn traverse_height<MT, H, G, M>(height: Height, g: &G, m: &M)
where
    H: 'static + Clone + Eq + fmt::Debug,
    G: GenLeaf<H>,
    M: MergeNodes<H>,
    MT: Eq + TraversableMerkleTree<H>,
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
        assert_eq!(apk, *mt.root());
        skn += 1;
        if !mt.next(g, m) {
            done = true;
        }
    }
    assert_eq!(skn, 1 << mt.height());
}

fn traverse_heights<MT, H, G, M>(max_height: Height, g: G, m: M)
where
    H: 'static + Clone + Eq + fmt::Debug,
    G: GenLeaf<H>,
    M: MergeNodes<H>,
    MT: Eq + TraversableMerkleTree<H>,
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
        traverse_height::<MT, H, G, M>(height, &g, &m);
    }
}

pub fn commutative<MT>()
where
    MT: Eq + TraversableMerkleTree<u64>,
{
    traverse_heights::<MT, _, _, _>(5, |idx| 1u64 << idx, |h0: &u64, h1: &u64| h0 | h1);
}

pub fn non_commutative<MT>()
where
    MT: Eq + TraversableMerkleTree<u64>,
{
    traverse_heights::<MT, _, _, _>(5, |idx| 1u64 << idx, |h0: &u64, h1: &u64| (h0 * 3 + h1) ^ 11);
}
