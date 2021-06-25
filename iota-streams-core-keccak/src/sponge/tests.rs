use super::prp::keccak::KeccakF1600;
use iota_streams_core::{
    prelude::typenum::Unsigned,
    sponge::{
        prp::PRP,
        tests::*,
    },
};

#[test]
fn tbits_with_size_boundary_cases_keccak_byte() {
    bytes_with_size_boundary_cases::<KeccakF1600>();
}

#[test]
fn slices_with_size_boundary_cases_keccak_byte() {
    slices_with_size_boundary_cases::<KeccakF1600>();
}

#[test]
fn encrypt_decrypt_keccak_byte() {
    let rate = <KeccakF1600 as PRP>::RateSize::USIZE;
    encrypt_decrypt_n::<KeccakF1600>(27);
    encrypt_decrypt_n::<KeccakF1600>(rate);
    encrypt_decrypt_n::<KeccakF1600>(rate - 28);
    encrypt_decrypt_n::<KeccakF1600>(rate + 28);
    encrypt_decrypt_n::<KeccakF1600>(2 * rate);
}
