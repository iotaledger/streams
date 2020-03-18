use iota_mam_core::tbits::binary::*;
use iota_mam_core::sponge::test::*;
use super::prp::keccak::KeccakF1600;

#[test]
fn tbits_with_size_boundary_cases_keccak() {
    tbits_with_size_boundary_cases::<Byte, KeccakF1600>();
}

#[test]
fn slices_with_size_boundary_cases_keccak() {
    slices_with_size_boundary_cases::<Byte, KeccakF1600>();
}
