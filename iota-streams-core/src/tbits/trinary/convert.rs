use std::convert::{From, TryFrom};
use std::num::Wrapping;

use super::defs::*;
use super::util::mods1;
use crate::tbits::{
    binary::Byte,
    convert::{log2e3, ConvertInto, ConvertIso},
    TbitSlice, TbitSliceMut,
};

impl From<Trit> for Trint1 {
    fn from(t: Trit) -> Trint1 {
        let x: u8 = (Wrapping(0) - Wrapping((t.0 >> 1) & 1)).0;
        Trint1((x | t.0) as i8)
    }
}

impl From<Trint1> for Trit {
    fn from(t: Trint1) -> Trit {
        let x = (t.0 as u8) & 3;
        Trit(x ^ (x >> 1))
    }
}

impl From<&[Trit; 3]> for Tryte {
    fn from(ts: &[Trit; 3]) -> Tryte {
        Tryte(ts[0].0 + 3 * (ts[1].0 + 3 * ts[2].0))
    }
}

impl From<[Trit; 3]> for Tryte {
    fn from(ts: [Trit; 3]) -> Tryte {
        Tryte::from(&ts)
    }
}

impl From<Tryte> for [Trit; 3] {
    fn from(t: Tryte) -> [Trit; 3] {
        let mut x = t.0;
        let t0 = Trit(x % 3);
        x /= 3;
        let t1 = Trit(x % 3);
        x /= 3;
        let t2 = Trit(x);
        [t0, t1, t2]
    }
}

impl From<&[Trint1; 3]> for Trint3 {
    fn from(ts: &[Trint1; 3]) -> Trint3 {
        Trint3(ts[0].0 + 3 * (ts[1].0 + 3 * ts[2].0))
    }
}

impl From<[Trint1; 3]> for Trint3 {
    fn from(ts: [Trint1; 3]) -> Trint3 {
        Trint3::from(&ts)
    }
}

impl From<Trint3> for [Trint1; 3] {
    fn from(t: Trint3) -> [Trint1; 3] {
        let (t0, q0) = mods1(t.0 as i32);
        let (t1, q1) = mods1(q0 as i32);
        let (t2, _) = mods1(q1 as i32);
        [t0, t1, t2]
    }
}

/// Convert tryte to char:
/// - `0 => '9'`;
/// - `1 => 'A'`;
/// - `13 => 'M'`;
/// - `14 => 'N'`;
/// - `26 => 'Z'`.
fn tryte_to_char(t: Tryte) -> char {
    debug_assert!(t.0 < 27);
    if t.0 == 0 {
        '9'
    } else {
        (t.0 - 1 + b'A') as char
    }
}

impl From<Tryte> for char {
    fn from(t: Tryte) -> char {
        tryte_to_char(t)
    }
}

/// Try convert char to tryte, returns `None` for invalid input char.
fn tryte_from_char(c: char) -> Result<Tryte, ()> {
    if 'A' <= c && c <= 'Z' {
        Ok(Tryte(c as u8 - b'A' + 1))
    } else if '9' == c {
        Ok(Tryte(0))
    } else {
        Err(())
    }
}

impl TryFrom<char> for Tryte {
    type Error = ();
    fn try_from(c: char) -> Result<Tryte, ()> {
        tryte_from_char(c)
    }
}

/// Convert tryte (which is unsigned) to trint3 (which is signed).
fn trint3_from_tryte(t: Tryte) -> Trint3 {
    debug_assert!(t.0 < 27);
    if 13 < t.0 {
        Trint3(t.0 as i8 - 27)
    } else {
        Trint3(t.0 as i8)
    }
}

impl From<Tryte> for Trint3 {
    fn from(t: Tryte) -> Trint3 {
        trint3_from_tryte(t)
    }
}

/// Convert tryte (which is unsigned) from trint3 (which is signed).
fn tryte_from_trint3(t: Trint3) -> Tryte {
    debug_assert!(-13 <= t.0 && t.0 <= 13);
    if t.0 < 0 {
        Tryte((t.0 + 27) as u8)
    } else {
        Tryte(t.0 as u8)
    }
}

impl From<Trint3> for Tryte {
    fn from(t: Trint3) -> Tryte {
        tryte_from_trint3(t)
    }
}

/// Convert trint3 to char.
fn trint3_to_char(t: Trint3) -> char {
    debug_assert!(-13 <= t.0 && t.0 <= 13);
    if t.0 < 0 {
        ((t.0 + 26) as u8 + b'A' as u8) as char
    } else if t.0 > 0 {
        ((t.0 - 1) as u8 + b'A' as u8) as char
    } else {
        '9'
    }
}

impl From<Trint3> for char {
    fn from(t: Trint3) -> char {
        trint3_to_char(t)
    }
}

/// Convert trint3 from char.
fn trint3_from_char(c: char) -> Result<Trint3, ()> {
    if 'A' <= c && c <= 'M' {
        Ok(Trint3(c as i8 - 'A' as i8 + 1))
    } else if 'N' <= c && c <= 'Z' {
        Ok(Trint3(c as i8 - 'A' as i8 - 26))
    } else if '9' == c {
        Ok(Trint3(0))
    } else {
        Err(())
    }
}

impl TryFrom<char> for Trint3 {
    type Error = ();
    fn try_from(c: char) -> Result<Trint3, ()> {
        trint3_from_char(c)
    }
}

impl ConvertInto<Byte> for Trit {
    fn cvt_into(mut from: TbitSlice<Trit>, into: &mut TbitSliceMut<Byte>) {
        assert!(from.size() < 10000);
        let b = log2e3(from.size() as u64) as usize;
        assert!(
            b < into.size(),
            "from.size={} b={} into.size={}",
            from.size(),
            b,
            into.size()
        );

        // Reserve (b+1)-bit integer.
        let mut integer = vec![0_u32; (b + 32) / 32];
        while !from.is_empty() {
            // integer = 3 * integer + trit
            //TODO: use larger base, eg. 243: convert chunks of 5 trits into u8 mod 243.
            let mut carry = from.advance(1).get_trit().0 as u32;
            for n in integer.iter_mut() {
                let v = 3 * (*n as u64) + carry as u64;
                *n = v as u32;
                carry = (v >> 32) as u32;
            }
        }

        let integer_slice = TbitSlice::<Byte>::from_raw_ptr(b + 1, integer.as_ptr() as *const Byte);
        integer_slice.copy(&into.advance(b + 1));
    }
}

impl ConvertIso<Byte> for Trit {}

/*
fn map_b8_into_t5_len(b8_len: usize) -> usize {
    // Full input space size in bits.
    let bit_count = b8_len * 8;
    // The minimum amount of trits required to represent the input.
    let min_trit_count = log3e2(bn) + 1;
    // Round up to whole number of words, 5 trits per word.
    let t5_len = (min_trit_count + 4) / 5;
    t5_len
}

/// Injection of 2⁸ᵇ into 3⁵ᵗ: ∀ x∈2⁸ᵇ ∃ y∈3⁵ᵗ
fn map_b8_into_t5(b8: &[u8], t5: &mut [u8]) {
    let b8_len = b8.len();
    let t5_len = map_b8_into_t5(b8_len);
    assert_eq!(t5_len, t5.len());

    const T: u8 = 243;
    const R: u8 = 13; // B = 256; B = T + R

    // Zeroize the high part of t5.
    for t in t5[t5_len - b8_len ..] { *t = 0; }

    for i in (0..b8_len).rev() {
        let b = b8[i];
        let mut q = (b / T) as u16;
        let mut r = (b % T) as u16;
        // b8[i..] ~ t5[i..] :=
        //  := b + B * t5[i+1..]
        //  == r + qT + (R + T) * t5[i+1..]
        //  == r + R t5[i+1..] + T (q + t5[i+1..])
        r = r + t5[i+1] as u16 * R as u16;
        t5[i] = (r % T as u16) as u8;
        r = q + (r / T as u16) + t5[i+2] * R;
        t5[i+1] = (r % T as u16) as u8;
        r = (r / T as u16) + t5[i+2] * R;
        t5[i+1] = (r % T as u16) as u8;
    }
}
/// Surjection of 2⁸ᵇ onto 3⁵ᵗ: ∀ y∈3⁵ᵗ ∃ x∈2⁸ᵇ
fn map_b8_onto_t5(b8: &[u8], t5: &mut [u8]) {
    let tn = t5.len() * 5;
    let bn = log2e3(tn) + 1;
}
 */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tbits::convert::{log2e3, log3e2};
    use crate::tbits::{binary::Byte, convert::ConvertIso, Tbits};

    fn map_b8_to_u128(b8: &[u8]) -> u128 {
        assert!(b8.len() <= 32);
        b8.iter().rev().fold(0u128, |n, b| n * 256 + *b as u128)
    }

    fn map_u128_to_b8(n: u128, b8: &mut [u8]) {
        let nn = b8.iter_mut().fold(n, |n, b| {
            *b = (n % 256) as u8;
            n / 256
        });
        assert_eq!(0, nn);
    }

    #[test]
    fn map_b8_u128() {
        let b8 = [1, 2, 3];
        let n = map_b8_to_u128(&b8);
        assert_eq!(n, 1 + 256 * (2 + 256 * 3));
        let mut bb8 = [0u8; 3];
        map_u128_to_b8(n, &mut bb8);
        assert_eq!(b8, bb8);
    }

    fn map_t5_to_u128(t5: &[u8]) -> u128 {
        assert!(t5.len() * 5 <= log3e2(128) as usize);
        t5.iter().rev().fold(0u128, |n, t| n * 243 + *t as u128)
    }

    fn map_u128_to_t5(n: u128, t5: &mut [u8]) {
        let nn = t5.iter_mut().fold(n, |n, t| {
            *t = (n % 243) as u8;
            n / 243
        });
        assert_eq!(0, nn);
    }

    #[test]
    fn map_t5_u128() {
        let t5 = [1, 2, 3];
        let n = map_t5_to_u128(&t5);
        assert_eq!(n, 1 + 243 * (2 + 243 * 3));
        let mut tt5 = [0u8; 3];
        map_u128_to_t5(n, &mut tt5);
        assert_eq!(t5, tt5);
    }

    #[test]
    fn trint3_tryte_char() {
        assert_eq!(Ok(Tryte(0)), Tryte::try_from('9'));
        assert_eq!(Ok(Tryte(1)), Tryte::try_from('A'));
        assert_eq!(Ok(Tryte(2)), Tryte::try_from('B'));
        assert_eq!(Ok(Tryte(13)), Tryte::try_from('M'));
        assert_eq!(Ok(Tryte(14)), Tryte::try_from('N'));
        assert_eq!(Ok(Tryte(26)), Tryte::try_from('Z'));

        assert_eq!(Ok(Trint3(0)), Trint3::try_from('9'));
        assert_eq!(Ok(Trint3(1)), Trint3::try_from('A'));
        assert_eq!(Ok(Trint3(2)), Trint3::try_from('B'));
        assert_eq!(Ok(Trint3(13)), Trint3::try_from('M'));
        assert_eq!(Ok(Trint3(-13)), Trint3::try_from('N'));
        assert_eq!(Ok(Trint3(-1)), Trint3::try_from('Z'));

        let alphabet = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for c in alphabet.chars() {
            assert_eq!(Ok(c), Tryte::try_from(c).map(char::from));
            assert_eq!(Ok(c), Trint3::try_from(c).map(char::from));
        }
        for t in MIN_TRINT3.0..=MAX_TRINT3.0 {
            let t = Trint3(t);
            assert_eq!(t, Trint3::from(Tryte::from(t)));
            assert_eq!(Ok(t), Trint3::try_from(char::from(t)));
            assert_eq!(char::from(Tryte::from(t)), char::from(t));
        }
        for t in MIN_TRYTE.0..=MAX_TRYTE.0 {
            let t = Tryte(t);
            assert_eq!(t, Tryte::from(Trint3::from(t)));
            assert_eq!(Ok(t), Tryte::try_from(char::from(t)));
            assert_eq!(char::from(Trint3::from(t)), char::from(t));
        }
    }

    #[test]
    fn trint3_trint1x3() {
        for t in MIN_TRINT3.0..=MAX_TRINT3.0 {
            let t = Trint3(t);
            assert_eq!(t, Trint3::from(Into::<[Trint1; 3]>::into(t)));
        }
    }

    #[test]
    fn tryte_tritx3() {
        for t in MIN_TRYTE.0..=MAX_TRYTE.0 {
            let t = Tryte(t);
            assert_eq!(t, Tryte::from(<[Trit; 3]>::from(t)));
        }
    }

    #[test]
    fn trit_trint1() {
        assert_eq!(Trint1::from(Trit(0)), Trint1(0));
        assert_eq!(Trint1::from(Trit(1)), Trint1(1));
        assert_eq!(Trint1::from(Trit(2)), Trint1(-1));

        assert_eq!(Trit(0), Trit::from(Trint1(0)));
        assert_eq!(Trit(1), Trit::from(Trint1(1)));
        assert_eq!(Trit(2), Trit::from(Trint1(-1)));
    }

    #[test]
    fn convert_into_byte() {
        let trits = Tbits::<Trit>::from_tbits(&[Trit(2); 250]);
        let mut bytes = Tbits::<Byte>::zero(250 * 8 / 5);

        let mut test = |n_trits, byte_str| {
            <Trit as ConvertInto<Byte>>::cvt_into(
                trits.slice().take(n_trits),
                &mut bytes.slice_mut(),
            );
            assert!(bytes
                .slice()
                .take(log2e3(n_trits as u64) as usize + 1)
                .eq_str(byte_str));
        };

        test(1, "2");
        test(5, "2F");
        test(6, "8D2");
        test(40, "028EF192254B8B8A");
        test(60, "0B5F1E29EF7ADEECEE429F88");
        test(120, "0644EE0BBECF0F060BB5E8BD24E11B987C51FB996B9A9494");
    }

    #[test]
    fn convert_iso_byte() {
        const NTRITS: usize = 2000;

        let trits = Tbits::<Trit>::from_tbits(&[Trit(2); NTRITS]);
        let mut trits2 = Tbits::<Trit>::zero(NTRITS);
        let mut bytes = Tbits::<Byte>::zero(NTRITS * 8 / 5);

        let mut test = |n_trits| {
            <Trit as ConvertInto<Byte>>::cvt_into(
                trits.slice().take(n_trits),
                &mut bytes.slice_mut(),
            );
            <Trit as ConvertIso<Byte>>::cvt_from(
                bytes.slice(),
                &mut trits2.slice_mut().take(n_trits),
            );
            assert_eq!(trits.slice().take(n_trits), trits2.slice().take(n_trits));
        };

        for n_trits in 0..NTRITS {
            test(n_trits);
        }
    }
}
