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
    let mut r = (t % 3) as i8;
    let mut q = t / 3;
    if r == 2 {
        r = -1;
        q += 1;
    }
    (Trint1(r), q)
}
/// Remainder `r` and quotient `q` of `t` `mods 3^3` where
/// `t == q * 3^3 + r` and `-13 <= r <= 13`.
pub fn mods3_usize(t: usize) -> (Trint3, usize) {
    let mut r = (t % 27) as i8;
    let mut q = t / 27;
    if 13 < r {
        r -= 27;
        q += 1;
    }
    (Trint3(r), q)
}

/// Remainder `r` and quotient `q` of `t` `mods 3^1` where
/// `t == q * 3^1 + r` and `-1 <= r <= 1`.
pub fn mods1(t: i32) -> (Trint1, i32) {
    let (r, q) = mods_i32(t, 3);
    (Trint1(r as i8), q)
}
/// Remainder `r` and quotient `q` of `t` `mods 3^3` where
/// `t == q * 3^3 + r` and `-13 <= r <= 13`.
pub fn mods3(t: i32) -> (Trint3, i32) {
    let (r, q) = mods_i32(t, 27);
    (Trint3(r as i8), q)
}
/// Remainder `r` and quotient `q` of `t` `mods 3^9` where
/// `t == q * 3^9 + r` and `-9841 <= r <= 9841`.
pub fn mods9(t: i32) -> (Trint9, i32) {
    let (r, q) = mods_i32(t, 19683);
    (Trint9(r as i16), q)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mods_i32(t: i32) {
        let m1 = 3;
        let m3 = 27;
        let m9 = 19683;

        let (r1, q1) = mods1(t);
        assert_eq!(t, r1.0 as i32 + q1 * m1);
        let (r3, q3) = mods3(t);
        assert_eq!(t, r3.0 as i32 + q3 * m3);
        let (r9, q9) = mods9(t);
        assert_eq!(t, r9.0 as i32 + q9 * m9);
    }
    fn mods_usize(t: usize) {
        let (ru, qu) = mods1_usize(t);
        let tt = if ru.0 < 0 {
            qu * 3 - (-ru.0) as usize
        } else {
            qu * 3 + ru.0 as usize
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
}
