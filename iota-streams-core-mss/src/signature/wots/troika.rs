use iota_streams_core::{
    hash::Hash,
    sponge::{
        prp::troika::Troika,
        spongos::Spongos,
    },
    tbits::{
        trinary::TritWord,
        word::{
            IntTbitWord,
            SpongosTbitWord,
        },
        TbitSlice,
        TbitSliceMut,
    },
};

pub struct KeyPartHash<TW>(Spongos<TW, Troika>);

impl<TW> Default for KeyPartHash<TW>
where
    TW: SpongosTbitWord + TritWord,
{
    fn default() -> Self {
        Self(Spongos::<TW, Troika>::init())
    }
}

impl<TW> Hash<TW> for KeyPartHash<TW>
where
    TW: SpongosTbitWord + TritWord,
{
    /// Hash value size in tbits.
    const HASH_SIZE: usize = 162;

    fn init() -> Self {
        Self(Spongos::<TW, Troika>::init())
    }
    fn update(&mut self, data: TbitSlice<TW>) {
        self.0.absorb(data);
    }
    fn done(&mut self, hash_value: &mut TbitSliceMut<TW>) {
        self.0.commit();
        self.0.squeeze(hash_value);
    }
}

pub struct Parameters<TW>(std::marker::PhantomData<TW>);

impl<TW> super::Parameters<TW> for Parameters<TW>
where
    TW: IntTbitWord + SpongosTbitWord + TritWord,
{
    type H = KeyPartHash<TW>;
    const HASH_PART_SIZE: usize = 3;
    const HASH_PART_MODULUS: usize = 27;
    const HASH_PART_COUNT: usize = 78;
    const CHECKSUM_PART_COUNT: usize = 3;
    type J = Spongos<TW, Troika>;
}

#[test]
fn sign_verify_troika() {
    use iota_streams_core::tbits::trinary::Trit;
    super::tests::sign_verify::<Trit, Parameters<Trit>, Troika>();
}
