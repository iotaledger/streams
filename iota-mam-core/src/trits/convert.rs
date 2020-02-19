use std::convert::{From, TryFrom};
use std::num::Wrapping;

use super::defs::*;
use super::util::mods1;

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

#[cfg(test)]
mod tests {
    use super::*;

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
        for t in MIN_TRINT3..=MAX_TRINT3 {
            assert_eq!(t, Trint3::from(Tryte::from(t)));
            assert_eq!(Ok(t), Trint3::try_from(char::from(t)));
            assert_eq!(char::from(Tryte::from(t)), char::from(t));
        }
        for t in MIN_TRYTE..=MAX_TRYTE {
            assert_eq!(t, Tryte::from(Trint3::from(t)));
            assert_eq!(Ok(t), Tryte::try_from(char::from(t)));
            assert_eq!(char::from(Trint3::from(t)), char::from(t));
        }
    }

    #[test]
    fn trint3_trint1x3() {
        for t in MIN_TRINT3..=MAX_TRINT3 {
            assert_eq!(t, Trint3::from(Into::<[Trint1; 3]>::into(t)));
        }
    }

    #[test]
    fn tryte_tritx3() {
        for t in MIN_TRYTE..=MAX_TRYTE {
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
}
