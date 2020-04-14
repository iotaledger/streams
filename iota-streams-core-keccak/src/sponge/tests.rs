use super::prp::keccak::{
    KeccakF1600B,
    KeccakF1600T,
};
use iota_streams_core::{
    sponge::{
        prp::PRP,
        tests::*,
    },
    tbits::{
        binary::Byte,
        trinary::Trit,
    },
};

#[test]
fn tbits_with_size_boundary_cases_keccak_byte() {
    tbits_with_size_boundary_cases::<Byte, KeccakF1600B>();
}

#[test]
fn slices_with_size_boundary_cases_keccak_byte() {
    slices_with_size_boundary_cases::<Byte, KeccakF1600B>();
}

#[test]
fn encrypt_decrypt_keccak_byte() {
    const RATE: usize = <KeccakF1600B as PRP<Byte>>::RATE;
    encrypt_decrypt_n::<Byte, KeccakF1600B>(27);
    encrypt_decrypt_n::<Byte, KeccakF1600B>(RATE);
    encrypt_decrypt_n::<Byte, KeccakF1600B>(RATE - 28);
    encrypt_decrypt_n::<Byte, KeccakF1600B>(RATE + 28);
    encrypt_decrypt_n::<Byte, KeccakF1600B>(2 * RATE);
}

#[test]
fn tbits_with_size_boundary_cases_keccak_trit() {
    tbits_with_size_boundary_cases::<Trit, KeccakF1600T>();
}

#[test]
fn slices_with_size_boundary_cases_keccak_trit() {
    slices_with_size_boundary_cases::<Trit, KeccakF1600T>();
}

#[test]
fn encrypt_decrypt_keccak_trit() {
    const RATE: usize = <KeccakF1600T as PRP<Trit>>::RATE;

    encrypt_decrypt_n::<Trit, KeccakF1600T>(27);
    encrypt_decrypt_n::<Trit, KeccakF1600T>(RATE);
    encrypt_decrypt_n::<Trit, KeccakF1600T>(RATE - 28);
    encrypt_decrypt_n::<Trit, KeccakF1600T>(RATE + 28);
    encrypt_decrypt_n::<Trit, KeccakF1600T>(2 * RATE);
}
