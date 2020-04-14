use crate::tbits::{
    word::BasicTbitWord,
    TbitSlice,
    TbitSliceMut,
    Tbits,
};

pub trait Hash<TW>: Sized {
    /// Hash value size in tbits.
    const HASH_SIZE: usize;

    fn init() -> Self;
    fn update(&mut self, data: TbitSlice<TW>);
    fn update_tbits(&mut self, data: &Tbits<TW>)
    where
        TW: BasicTbitWord,
    {
        self.update(data.slice());
    }
    fn done(&mut self, hash_value: &mut TbitSliceMut<TW>);
    fn done_tbits(&mut self) -> Tbits<TW>
    where
        TW: BasicTbitWord,
    {
        let mut hash_value = Tbits::<TW>::zero(Self::HASH_SIZE);
        self.done(&mut hash_value.slice_mut());
        hash_value
    }

    /// Hash data.
    fn hash(data: TbitSlice<TW>, hash_value: &mut TbitSliceMut<TW>) {
        let mut s = Self::init();
        s.update(data);
        s.done(hash_value);
    }

    /// Hash data.
    fn hash_tbits(data: Tbits<TW>) -> Tbits<TW>
    where
        TW: BasicTbitWord,
    {
        let mut hash_value = Tbits::zero(Self::HASH_SIZE);
        Self::hash(data.slice(), &mut hash_value.slice_mut());
        hash_value
    }

    fn rehash(value: &mut TbitSliceMut<TW>)
    where
        TW: BasicTbitWord,
    {
        unsafe {
            Self::hash(value.as_const(), value);
        }
    }

    fn rehash_tbits(value: &mut Tbits<TW>)
    where
        TW: BasicTbitWord,
    {
        Self::rehash(&mut value.slice_mut());
    }
}
