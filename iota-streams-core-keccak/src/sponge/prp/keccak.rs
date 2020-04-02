use iota_streams_core::sponge::prp::{inner, Mode, PRP};
use iota_streams_core::tbits::{
    binary::Byte, convert::*, word::BasicTbitWord, TbitSlice, TbitSliceMut, Tbits,
};
use keccak;

#[derive(Clone)]
pub struct KeccakF1600B {
    state: [u64; 25],
}

impl Default for KeccakF1600B {
    fn default() -> Self {
        Self { state: [0u64; 25] }
    }
}

impl KeccakF1600B {
    pub fn permutation(&mut self) {
        keccak::f1600(&mut self.state);
    }
}

#[derive(Clone)]
pub struct KeccakF1600T {
    state: [u64; 25],
}

impl Default for KeccakF1600T {
    fn default() -> Self {
        Self { state: [0u64; 25] }
    }
}

impl KeccakF1600T {
    pub fn permutation(&mut self) {
        keccak::f1600(&mut self.state);
    }
}

fn keccakf1600_transform<TW>(state: &mut [u64; 25], outer: &mut TbitSliceMut<TW>)
where
    TW: BasicTbitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    unsafe {
        let state_bytes: &mut [Byte; 25 * 8] = std::mem::transmute(&mut *state);
        let mut bits = TbitSliceMut::<Byte>::from_slice_mut(25 * 8 * 8, state_bytes);
        <TW as ConvertInto<Byte>>::cvt_into(outer.as_const(), &mut bits);
    }
    keccak::f1600(state);
    unsafe {
        let state_bytes: &[Byte; 25 * 8] = std::mem::transmute(&*state);
        let bits = TbitSlice::<Byte>::from_slice(25 * 8 * 8, state_bytes);
        <TW as ConvertIso<Byte>>::cvt_from(bits, outer);
    }
}

fn inner_into_keccakf1600(state: &mut [u64; 25], inner: TbitSlice<Byte>) {
    unsafe {
        let state_bytes: &mut [Byte; 25 * 8] = std::mem::transmute(&mut *state);
        let bits = TbitSliceMut::<Byte>::from_slice_mut(25 * 8 * 8, state_bytes);
        inner.copy(&bits.take(inner.size()));
    }
}

fn inner_from_keccakf1600(state: &[u64; 25], inner: TbitSliceMut<Byte>) {
    unsafe {
        let state_bytes: &[Byte; 25 * 8] = std::mem::transmute(&*state);
        let bits = TbitSlice::<Byte>::from_slice(25 * 8 * 8, state_bytes);
        bits.take(inner.size()).copy(&inner);
    }
}

impl Into<KeccakF1600B> for inner::Inner<Byte, KeccakF1600B> {
    fn into(self) -> KeccakF1600B {
        //assert!(self.inner.size() <= 1600);
        assert_eq!(256, self.inner.size());
        let mut k = KeccakF1600B::default();
        inner_into_keccakf1600(&mut k.state, self.inner.slice());
        k
    }
}

impl Into<KeccakF1600T> for inner::Inner<Byte, KeccakF1600T> {
    fn into(self) -> KeccakF1600T {
        //assert!(self.inner.size() <= 1600);
        assert_eq!(log2e3(243) as usize + 1, self.inner.size());
        let mut k = KeccakF1600T::default();
        inner_into_keccakf1600(&mut k.state, self.inner.slice());
        k
    }
}

impl From<KeccakF1600B> for inner::Inner<Byte, KeccakF1600B> {
    fn from(s: KeccakF1600B) -> Self {
        let mut inn = inner::Inner {
            inner: Tbits::<Byte>::zero(256),
            _phantom: std::marker::PhantomData,
        };
        inner_from_keccakf1600(&s.state, inn.inner.slice_mut());
        inn
    }
}

impl From<KeccakF1600T> for inner::Inner<Byte, KeccakF1600T> {
    fn from(s: KeccakF1600T) -> Self {
        let mut inn = inner::Inner {
            inner: Tbits::<Byte>::zero(log2e3(243) as usize + 1),
            _phantom: std::marker::PhantomData,
        };
        inner_from_keccakf1600(&s.state, inn.inner.slice_mut());
        inn
    }
}

impl<TW> PRP<TW> for KeccakF1600B
where
    TW: BasicTbitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    const RATE: usize = 1600 - 256;

    const CAPACITY: usize = 256;

    const MODE: Mode = Mode::XOR;

    fn transform(&mut self, outer: &mut TbitSliceMut<TW>) {
        keccakf1600_transform(&mut self.state, outer);
    }

    type Inner = inner::Inner<Byte, KeccakF1600B>;
}

impl<TW> PRP<TW> for KeccakF1600T
where
    TW: BasicTbitWord + ConvertIso<Byte>,
    Byte: ConvertOnto<TW>,
{
    const RATE: usize = log3e2(1600) as usize - 243 - 1;

    const CAPACITY: usize = 243;

    const MODE: Mode = Mode::XOR;

    fn transform(&mut self, outer: &mut TbitSliceMut<TW>) {
        keccakf1600_transform(&mut self.state, outer);
    }

    type Inner = inner::Inner<Byte, KeccakF1600T>;
}

#[test]
fn test_keccakf1600t_transform() {
    use iota_streams_core::tbits::{trinary::Trit, Tbits};
    let mut s = KeccakF1600T::default();
    let mut outer = Tbits::<Trit>::zero(<KeccakF1600T as PRP<Trit>>::RATE);
    s.transform(&mut outer.slice_mut());
}
