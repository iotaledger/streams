use super::defs::*;

/// Abstraction for a trinary word containing one or several trits.
/// The size and encoding of trinary word is defined by the implementation.
/// Many functions take a pair `(d,p)` encoding a slice of trits as input where
/// `d` is the current trit offset, `p` is the raw pointer to the first word in a slice.
pub trait TritWord {
    /// The number of trits per word.
    const SIZE: usize;

    /// All-zero trits word.
    fn zero() -> Self;
    /// Copy `n` trits from `(dx,x)` slice into `(dy,y)`.
    fn unsafe_copy(n: usize, dx: usize, x: *const Self, dy: usize, y: *mut Self);
    /// Set `n` trits in `(d,p)` slice to zero.
    fn unsafe_set_zero(n: usize, d: usize, p: *mut Self);
    /// Compare `n` trits from `(dx,x)` slice into `(dy,y)`.
    fn unsafe_eq(n: usize, dx: usize, x: *const Self, dy: usize, y: *const Self) -> bool;

    // Integer conversion utils

    fn put_trit(d: usize, p: *mut Self, t: Trit);
    fn get_trit(d: usize, p: *const Self) -> Trit;
    fn put_tryte(d: usize, p: *mut Self, t: Tryte);
    fn get_tryte(d: usize, p: *const Self) -> Tryte;
    fn put1(d: usize, p: *mut Self, t: Trint1);
    fn get1(d: usize, p: *const Self) -> Trint1;
    fn put3(d: usize, p: *mut Self, t: Trint3);
    fn get3(d: usize, p: *const Self) -> Trint3;
    fn put6(d: usize, p: *mut Self, t: Trint6);
    fn get6(d: usize, p: *const Self) -> Trint6;
    fn put9(d: usize, p: *mut Self, t: Trint9);
    fn get9(d: usize, p: *const Self) -> Trint9;
    fn put18(d: usize, p: *mut Self, t: Trint18);
    fn get18(d: usize, p: *const Self) -> Trint18;

    // Spongos-related utils

    /// y:=x+s, s:=x, x:=y
    fn unsafe_swap_add(n: usize, dx: usize, x: *mut Self, ds: usize, s: *mut Self);
    /// x:=y-s, s:=x, y:=x
    fn unsafe_swap_sub(n: usize, dy: usize, y: *mut Self, ds: usize, s: *mut Self);
    /// y:=x+s, s:=x
    fn unsafe_copy_add(
        n: usize,
        dx: usize,
        x: *const Self,
        ds: usize,
        s: *mut Self,
        dy: usize,
        y: *mut Self,
    );
    /// t:=y-s, s:=t, x:=t
    fn unsafe_copy_sub(
        n: usize,
        dy: usize,
        y: *const Self,
        ds: usize,
        s: *mut Self,
        dx: usize,
        x: *mut Self,
    );
}
