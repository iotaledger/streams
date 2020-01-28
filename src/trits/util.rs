use super::defs::*;

/// `std::i32::MIN + (m-1)/2 < t && t < std::i32::MAX - (m-1)/2`.
fn mods_i32(t: i32, m: i32) -> (i32, i32) {
    //TODO: Simplify to avoid triple division (third division is in `q`).
    let r = (((t % m) + m + (m - 1) / 2) % m) - (m - 1) / 2;
    //TODO: Deal with overflows of `i32` type.
    let q = (t - r) / m;
    (r, q)
}

/// Remainder `r` and quotient `q` of `t` `mods 3^1` where
/// `t == q * 3^1 + r` and `-1 <= r <= 1`.
pub fn mods1_usize(t: usize) -> (Trint1, usize) {
    let mut r = (t % 3) as Trint1;
    let mut q = t / 3;
    if r == 2 {
        r = -1;
        q += 1;
    }
    (r, q)
}
/// Remainder `r` and quotient `q` of `t` `mods 3^3` where
/// `t == q * 3^3 + r` and `-13 <= r <= 13`.
pub fn mods3_usize(t: usize) -> (Trint3, usize) {
    let mut r = (t % 27) as Trint3;
    let mut q = t / 27;
    if 13 < r {
        r -= 27;
        q += 1;
    }
    (r, q)
}

/// Remainder `r` and quotient `q` of `t` `mods 3^1` where
/// `t == q * 3^1 + r` and `-1 <= r <= 1`.
pub fn mods1(t: i32) -> (Trint1, i32) {
    let (r, q) = mods_i32(t, 3);
    (r as Trint1, q)
}
/// Remainder `r` and quotient `q` of `t` `mods 3^3` where
/// `t == q * 3^3 + r` and `-13 <= r <= 13`.
pub fn mods3(t: i32) -> (Trint3, i32) {
    let (r, q) = mods_i32(t, 27);
    (r as Trint3, q)
}
/// Remainder `r` and quotient `q` of `t` `mods 3^9` where
/// `t == q * 3^9 + r` and `-9841 <= r <= 9841`.
pub fn mods9(t: i32) -> (Trint9, i32) {
    let (r, q) = mods_i32(t, 19683);
    (r as Trint9, q)
}

/// Convert tryte to char:
/// - `0 => '9'`;
/// - `1 => 'A'`;
/// - `13 => 'M'`;
/// - `14 => 'N'`;
/// - `26 => 'Z'`.
pub fn tryte_to_char(t: Tryte) -> char {
    debug_assert!(t < 27);
    if t == 0 {
        '9'
    } else {
        (t - 1 + b'A') as char
    }
}
/// Try convert char to tryte, returns `None` for invalid input char.
///
/// ```rust
/// use iota_mam::trits::{defs::*, util::*};
/// for t in 0 as Tryte .. 26 {
///     assert_eq!(Some(t), tryte_from_char(tryte_to_char(t)));
/// }
/// ```
pub fn tryte_from_char(c: char) -> Option<Tryte> {
    if 'A' <= c && c <= 'Z' {
        Some(c as Tryte - b'A' + 1)
    } else if '9' == c {
        Some(0)
    } else {
        None
    }
}

/// Convert tryte (which is unsigned) to trint3 (which is signed).
pub fn tryte_to_trint3(t: Tryte) -> Trint3 {
    debug_assert!(t < 27);
    if 13 < t {
        (t as Trint3) - 27
    } else {
        t as Trint3
    }
}
/// Convert tryte (which is unsigned) from trint3 (which is signed).
///
/// ```rust
/// use iota_mam::trits::util::*;
/// for t in 0 .. 26 {
///     assert_eq!(t, tryte_from_trint3(tryte_to_trint3(t)));
/// }
/// ```
pub fn tryte_from_trint3(t: Trint3) -> Tryte {
    debug_assert!(-13 <= t && t <= 13);
    if t < 0 {
        (t + 27) as Tryte
    } else {
        t as Tryte
    }
}

/// Convert trint3 to char.
///
/// ```rust
/// use iota_mam::trits::util::*;
/// for t in -13 .. 13 {
///     assert_eq!(tryte_to_char(tryte_from_trint3(t)), trint3_to_char(t));
/// }
/// ```
pub fn trint3_to_char(t: Trint3) -> char {
    debug_assert!(-13 <= t && t <= 13);
    if t < 0 {
        ((t + 26 + 'A' as Trint3) as u8) as char
    } else if t > 0 {
        ((t - 1 + 'A' as Trint3) as u8) as char
    } else {
        '9'
    }
}
/// Convert trint3 from char.
///
/// ```rust
/// use iota_mam::trits::util::*;
/// let s = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// for c in s.chars() {
///     assert_eq!(tryte_from_char(c).map(tryte_to_trint3), trint3_from_char(c));
/// }
/// ```
pub fn trint3_from_char(c: char) -> Option<Trint3> {
    if 'A' <= c && c <= 'M' {
        Some(c as Trint3 - 'A' as Trint3 + 1)
    } else if 'N' <= c && c <= 'Z' {
        Some(c as Trint3 - 'A' as Trint3 - 26)
    } else if '9' == c {
        Some(0)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mods_i32(t: i32) {
        let m1 = 3;
        let m3 = 27;
        let m9 = 19683;

        let (r1, q1) = mods1(t);
        assert_eq!(t, r1 as i32 + q1 * m1);
        let (r3, q3) = mods3(t);
        assert_eq!(t, r3 as i32 + q3 * m3);
        let (r9, q9) = mods9(t);
        assert_eq!(t, r9 as i32 + q9 * m9);
    }
    fn mods_usize(t: usize) {
        let (ru, qu) = mods1_usize(t);
        let tt = if ru < 0 {
            qu * 3 - (-ru) as usize
        } else {
            qu * 3 + ru as usize
        };
        assert_eq!(t, tt);
    }

    #[test]
    fn mods() {
        let r: i32 = 3 * 19683;
        for t in -r..r {
            mods_i32(t);
        }
        /*
        mods_i32(std::i32::MAX);
        mods_i32(std::i32::MAX-1);
        mods_i32(std::i32::MAX-2);
        mods_i32(std::i32::MIN+2);
        mods_i32(std::i32::MIN+1);
        mods_i32(std::i32::MIN);
         */

        for t in 0_usize..100_usize {
            mods_usize(t);
        }
        /*
        mods_usize(std::usize::MAX);
        mods_usize(std::usize::MAX-1);
        mods_usize(std::usize::MAX-2);
         */
    }

    #[test]
    fn char() {
        assert_eq!(Some(0), tryte_from_char('9'));
        assert_eq!(Some(1), tryte_from_char('A'));
        assert_eq!(Some(2), tryte_from_char('B'));
        assert_eq!(Some(13), tryte_from_char('M'));
        assert_eq!(Some(14), tryte_from_char('N'));
        assert_eq!(Some(26), tryte_from_char('Z'));

        assert_eq!(Some(0), trint3_from_char('9'));
        assert_eq!(Some(1), trint3_from_char('A'));
        assert_eq!(Some(2), trint3_from_char('B'));
        assert_eq!(Some(13), trint3_from_char('M'));
        assert_eq!(Some(-13), trint3_from_char('N'));
        assert_eq!(Some(-1), trint3_from_char('Z'));
    }
}
