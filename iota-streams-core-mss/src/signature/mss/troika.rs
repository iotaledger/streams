use crate::signature::wots;
use iota_streams_core::{
    sponge::prp,
    tbits::{
        trinary::TritWord,
        word::{
            IntTbitWord,
            SpongosTbitWord,
        },
        Tbits,
    },
};
use iota_streams_core_merkletree::merkle_tree;

pub struct ParametersMtTraversal<TW>(std::marker::PhantomData<TW>);

impl<TW> super::Parameters<TW> for ParametersMtTraversal<TW>
where
    TW: IntTbitWord + SpongosTbitWord + TritWord,
{
    type PrngG = prp::troika::Troika;

    type WotsParameters = wots::troika::Parameters<TW>;

    /// Tbits needed to encode tree height part of SKN.
    const SKN_TREE_HEIGHT_SIZE: usize = 4;

    /// Tbits needed to encode key number part of SKN.
    const SKN_KEY_NUMBER_SIZE: usize = 14;

    type MerkleTree = merkle_tree::traversal::MT<Tbits<TW>>;

    /// Max Merkle tree height.
    const MAX_D: usize = 20;
}
/*
 */

pub struct ParametersMtComplete<TW>(std::marker::PhantomData<TW>);

impl<TW> super::Parameters<TW> for ParametersMtComplete<TW>
where
    TW: IntTbitWord + SpongosTbitWord + TritWord,
{
    type PrngG = prp::troika::Troika;

    type WotsParameters = wots::troika::Parameters<TW>;

    /// Tbits needed to encode tree height part of SKN.
    const SKN_TREE_HEIGHT_SIZE: usize = 4;

    /// Tbits needed to encode key number part of SKN.
    const SKN_KEY_NUMBER_SIZE: usize = 14;

    type MerkleTree = merkle_tree::complete::MT<Tbits<TW>>;

    /// Max Merkle tree height.
    const MAX_D: usize = 20;
}

#[test]
fn sign_verify_d2_mtcomplete() {
    use iota_streams_core::tbits::trinary::Trit;
    super::tests::sign_verify::<Trit, ParametersMtComplete<Trit>>();
}

#[test]
fn sign_verify_d2_mttraversal() {
    use iota_streams_core::tbits::trinary::Trit;
    super::tests::sign_verify::<Trit, ParametersMtTraversal<Trit>>();
}
/*
 */
