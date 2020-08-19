use super::prp::keccak::KeccakF1600;
use iota_streams_core::sponge::{
    prp::PRP,
    tests::*,
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
    const RATE: usize = <KeccakF1600 as PRP>::RATE;
    encrypt_decrypt_n::<KeccakF1600>(27);
    encrypt_decrypt_n::<KeccakF1600>(RATE);
    encrypt_decrypt_n::<KeccakF1600>(RATE - 28);
    encrypt_decrypt_n::<KeccakF1600>(RATE + 28);
    encrypt_decrypt_n::<KeccakF1600>(2 * RATE);
}
