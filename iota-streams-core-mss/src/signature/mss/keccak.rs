use crate::signature::wots;
use iota_streams_core::tbits::{
    binary::{BitWord, Byte},
    convert::*,
    trinary::TritWord,
    word::{IntTbitWord, SpongosTbitWord},
    Tbits,
};
use iota_streams_core_keccak::sponge::prp;
use iota_streams_core_merkletree::merkle_tree;

pub struct ParametersMtTraversalT<TW>(std::marker::PhantomData<TW>);

impl<TW> super::Parameters<TW> for ParametersMtTraversalT<TW>
where
    TW: IntTbitWord + SpongosTbitWord + TritWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    type PrngG = prp::keccak::KeccakF1600T;

    type WotsParameters = wots::keccak::ParametersT<TW>;

    /// Tbits needed to encode tree height part of SKN.
    const SKN_TREE_HEIGHT_SIZE: usize = 4;

    /// Tbits needed to encode key number part of SKN.
    const SKN_KEY_NUMBER_SIZE: usize = 14;

    type MerkleTree = merkle_tree::traversal::MT<Tbits<TW>>;

    /// Max Merkle tree height.
    const MAX_D: usize = 20;
}

pub struct ParametersMtCompleteT<TW>(std::marker::PhantomData<TW>);

impl<TW> super::Parameters<TW> for ParametersMtCompleteT<TW>
where
    TW: IntTbitWord + SpongosTbitWord + TritWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    type PrngG = prp::keccak::KeccakF1600T;

    type WotsParameters = wots::keccak::ParametersT<TW>;

    /// Tbits needed to encode tree height part of SKN.
    const SKN_TREE_HEIGHT_SIZE: usize = 4;

    /// Tbits needed to encode key number part of SKN.
    const SKN_KEY_NUMBER_SIZE: usize = 14;

    type MerkleTree = merkle_tree::complete::MT<Tbits<TW>>;

    /// Max Merkle tree height.
    const MAX_D: usize = 20;
}

pub struct ParametersMtTraversalB<TW>(std::marker::PhantomData<TW>);

impl<TW> super::Parameters<TW> for ParametersMtTraversalB<TW>
where
    TW: IntTbitWord + SpongosTbitWord + BitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    type PrngG = prp::keccak::KeccakF1600B;

    type WotsParameters = wots::keccak::ParametersB<TW>;

    /// Tbits needed to encode tree height part of SKN.
    const SKN_TREE_HEIGHT_SIZE: usize = 8;

    /// Tbits needed to encode key number part of SKN.
    const SKN_KEY_NUMBER_SIZE: usize = 16;

    type MerkleTree = merkle_tree::traversal::MT<Tbits<TW>>;

    /// Max Merkle tree height.
    const MAX_D: usize = 16;
}

pub struct ParametersMtCompleteB<TW>(std::marker::PhantomData<TW>);

impl<TW> super::Parameters<TW> for ParametersMtCompleteB<TW>
where
    TW: IntTbitWord + SpongosTbitWord + BitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    type PrngG = prp::keccak::KeccakF1600B;

    type WotsParameters = wots::keccak::ParametersB<TW>;

    /// Tbits needed to encode tree height part of SKN.
    const SKN_TREE_HEIGHT_SIZE: usize = 8;

    /// Tbits needed to encode key number part of SKN.
    const SKN_KEY_NUMBER_SIZE: usize = 16;

    type MerkleTree = merkle_tree::complete::MT<Tbits<TW>>;

    /// Max Merkle tree height.
    const MAX_D: usize = 16;
}

#[test]
fn sign_verify_d2_mtcomplete_keccakt() {
    use iota_streams_core::tbits::trinary::Trit;
    super::tests::sign_verify::<Trit, ParametersMtCompleteT<Trit>>();
}

#[test]
fn sign_verify_d2_mttraversal_keccakt() {
    use iota_streams_core::tbits::trinary::Trit;
    super::tests::sign_verify::<Trit, ParametersMtTraversalT<Trit>>();
}

#[test]
fn sign_verify_d2_mtcomplete_keccakb() {
    super::tests::sign_verify::<Byte, ParametersMtCompleteB<Byte>>();
}

#[test]
fn sign_verify_d2_mttraversal_keccakb() {
    super::tests::sign_verify::<Byte, ParametersMtTraversalB<Byte>>();
}
