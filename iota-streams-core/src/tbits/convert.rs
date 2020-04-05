use super::slice::{TbitSlice, TbitSliceMut};
use super::word::BasicTbitWord;

/// Injection
pub trait ConvertInto<IntoW>: Sized {
    fn cvt_into(from: TbitSlice<Self>, into: &mut TbitSliceMut<IntoW>);
}

impl<TW> ConvertInto<TW> for TW
where
    TW: BasicTbitWord,
{
    fn cvt_into(from: TbitSlice<TW>, into: &mut TbitSliceMut<TW>) {
        let n = from.size();
        assert!(n <= into.size());
        from.copy(&into.advance(n));
    }
}

/// Surjection
pub trait ConvertOnto<OntoW>: Sized {
    fn cvt_onto(from: TbitSlice<Self>, onto: &mut TbitSliceMut<OntoW>);
}

impl<TW> ConvertOnto<TW> for TW
where
    TW: BasicTbitWord,
{
    fn cvt_onto(from: TbitSlice<TW>, onto: &mut TbitSliceMut<TW>) {
        let n = onto.size();
        assert!(n <= from.size());
        from.take(n).copy(&onto.advance(n));
    }
}

pub trait ConvertIso<IsoW>: Sized
where
    Self: ConvertInto<IsoW>,
    IsoW: ConvertOnto<Self>,
{
    fn cvt_from(from: TbitSlice<IsoW>, onto: &mut TbitSliceMut<Self>) {
        <IsoW as ConvertOnto<Self>>::cvt_onto(from, onto)
    }
}

impl<TW> ConvertIso<TW> for TW where TW: BasicTbitWord {}

// For t<10000 return b such that 2ᵇ < 3ᵗ < 2ᵇ⁺¹.
pub const fn log2e3(t: u64) -> u64 {
    // T/B is a closest rational approximation of log(2)/log(3)
    // calculated with Farey algorithm with respect to accuracy of f64 type.
    const T: u64 = 96650392;
    const B: u64 = 153187247;
    //assert!(t < 14936);
    B * t / T
}

// For b<15000 return t such that 3ᵗ < 2ᵇ < 3ᵗ⁺¹.
pub const fn log3e2(b: u64) -> u64 {
    // T/B is a closest rational approximation of log(2)/log(3)
    // calculated with Farey algorithm with respect to accuracy of f64 type.
    const T: u64 = 96650392;
    const B: u64 = 153187247;
    //assert!(t < 14936);
    T * b / B
}

#[cfg(test)]
mod farey {
    fn farey(x: f64, n: u64) -> (u64, u64) {
        let mut a = 0;
        let mut b = 1;
        let mut c = 1;
        let mut d = 1;

        while b <= n && d <= n {
            let m = (a + c) as f64 / (b + d) as f64;
            if x > m {
                a += c;
                b += d;
            } else if x < m {
                c += a;
                d += b;
            } else {
                if b + d <= n {
                    return (a + c, b + d);
                } else if d > b {
                    return (c, d);
                } else {
                    return (a, b);
                }
            }
        }

        if b > n {
            (c, d)
        } else {
            (a, b)
        }
    }

    #[test]
    fn run_rational_approx() {
        const NS: [u64; 7] = [
            1000,
            10000,
            100000,
            1000000,
            1200000,
            1000000000,
            1000000000000,
        ];
        let e = 2.0_f64.log2() / 3.0_f64.log2();
        for k in &NS {
            let (n, d) = farey(e, *k);
            println!("{} =~ {}/{} + {}", e, n, d, e - n as f64 / d as f64);
        }

        assert_eq!((96650392_u64, 153187247_u64), farey(e, 1000000000));
    }
}
