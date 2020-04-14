use iota_streams_core::{
    hash::Hash,
    sponge::spongos::Spongos,
    tbits::{
        binary::{
            BitWord,
            Byte,
        },
        convert::*,
        trinary::TritWord,
        word::{
            IntTbitWord,
            SpongosTbitWord,
        },
        TbitSlice,
        TbitSliceMut,
    },
};
use iota_streams_core_keccak::sponge::prp::keccak::{
    KeccakF1600B,
    KeccakF1600T,
};

pub struct KeyPartHashT<TW>(Spongos<TW, KeccakF1600T>);

impl<TW> Default for KeyPartHashT<TW>
where
    TW: SpongosTbitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
    //TW: SpongosTbitWord + TritWord,
{
    fn default() -> Self {
        Self(Spongos::<TW, KeccakF1600T>::init())
    }
}

impl<TW> Hash<TW> for KeyPartHashT<TW>
where
    TW: SpongosTbitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    /// Hash value size in tbits.
    const HASH_SIZE: usize = 162;

    fn init() -> Self {
        Self(Spongos::<TW, KeccakF1600T>::init())
    }
    fn update(&mut self, data: TbitSlice<TW>) {
        self.0.absorb(data);
    }
    fn done(&mut self, hash_value: &mut TbitSliceMut<TW>) {
        self.0.commit();
        self.0.squeeze(hash_value);
    }
}

pub struct ParametersT<TW>(std::marker::PhantomData<TW>);

impl<TW> super::Parameters<TW> for ParametersT<TW>
where
    TW: IntTbitWord + SpongosTbitWord + TritWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    type H = KeyPartHashT<TW>;
    const HASH_PART_SIZE: usize = 3;
    const HASH_PART_MODULUS: usize = 27;
    const HASH_PART_COUNT: usize = 78;
    const CHECKSUM_PART_COUNT: usize = 3;
    type J = Spongos<TW, KeccakF1600T>;
}

pub struct KeyPartHashB<TW>(Spongos<TW, KeccakF1600B>);

impl<TW> Default for KeyPartHashB<TW>
where
    TW: SpongosTbitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    fn default() -> Self {
        Self(Spongos::<TW, KeccakF1600B>::init())
    }
}

impl<TW> Hash<TW> for KeyPartHashB<TW>
where
    TW: SpongosTbitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    /// Hash value size in tbits.
    const HASH_SIZE: usize = 192;

    fn init() -> Self {
        Self(Spongos::<TW, KeccakF1600B>::init())
    }
    fn update(&mut self, data: TbitSlice<TW>) {
        self.0.absorb(data);
    }
    fn done(&mut self, hash_value: &mut TbitSliceMut<TW>) {
        self.0.commit();
        self.0.squeeze(hash_value);
    }
}

pub struct ParametersB<TW>(std::marker::PhantomData<TW>);

impl<TW> super::Parameters<TW> for ParametersB<TW>
where
    TW: IntTbitWord + SpongosTbitWord + BitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    type H = KeyPartHashB<TW>;
    const HASH_PART_SIZE: usize = 4;
    const HASH_PART_MODULUS: usize = 1 << Self::HASH_PART_SIZE;
    const HASH_PART_COUNT: usize = 61;
    const CHECKSUM_PART_COUNT: usize = 3;
    type J = Spongos<TW, KeccakF1600B>;
}

#[test]
fn sign_verify_keccakt() {
    use iota_streams_core::tbits::trinary::Trit;
    super::tests::sign_verify::<Trit, ParametersT<Trit>, KeccakF1600T>();
}

#[test]
fn sign_verify_keccakb() {
    super::tests::sign_verify::<Byte, ParametersB<Byte>, KeccakF1600B>();
}
