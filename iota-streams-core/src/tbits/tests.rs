use std::{
    fmt,
    str::FromStr,
};

use super::{
    word::*,
    *,
};

fn copy_range_tbits<TW>(m: usize, n: usize, ts: &[TW::Tbit])
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display + fmt::Debug,
{
    let t0 = Tbits::<TW>::from_tbits(&ts[..m]);
    let t1 = Tbits::<TW>::from_tbits(&ts[m..n]);
    let t2 = Tbits::<TW>::from_tbits(&ts[n..]);
    let t012 = Tbits::<TW>::from_tbits(&ts);

    let to_tbits = |t: TbitSlice<TW>| {
        let mut v = vec![TW::ZERO_TBIT; t.size()];
        t.get_tbits(&mut v[..]);
        v
    };

    let mut x0 = Tbits::<TW>::zero(ts.len());
    x0.slice_mut().put_tbits(ts);
    assert_eq!(t012, x0);
    assert_eq!(ts, &to_tbits(x0.slice())[..]);

    let mut x1 = Tbits::<TW>::zero(ts.len());
    x1.slice_mut().take(m).put_tbits(&ts[..m]);
    x1.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
    x1.slice_mut().drop(n).put_tbits(&ts[n..]);
    assert_eq!(t012, x1);
    assert_eq!(ts, &to_tbits(x1.slice())[..]);

    let mut x2 = Tbits::<TW>::zero(ts.len());
    x2.slice_mut().drop(n).put_tbits(&ts[n..]);
    x2.slice_mut().take(m).put_tbits(&ts[..m]);
    x2.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
    assert_eq!(t012, x2);
    assert_eq!(t0.slice(), x2.slice().take(m));
    assert_eq!(t1.slice(), x2.slice().drop(m).take(n - m));
    assert_eq!(t2.slice(), x2.slice().drop(n));
    assert_eq!(ts, &to_tbits(x2.slice())[..]);
    assert_eq!(ts[..m], to_tbits(x2.slice().take(m))[..]);
    assert_eq!(ts[m..n], to_tbits(x2.slice().drop(m).take(n - m))[..]);
    assert_eq!(ts[n..], to_tbits(x2.slice().drop(n))[..]);
    x2.slice_mut().set_zero();
    x2.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
    x2.slice_mut().drop(n).put_tbits(&ts[n..]);
    x2.slice_mut().take(m).put_tbits(&ts[..m]);
    assert_eq!(t012, x2);
    x2.slice_mut().take(m).set_zero();
    x2.slice_mut().take(m).put_tbits(&ts[..m]);
    x2.slice_mut().drop(m).take(n - m).set_zero();
    x2.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
    x2.slice_mut().drop(n).set_zero();
    x2.slice_mut().drop(n).put_tbits(&ts[n..]);
    assert_eq!(t012, x2);
    x2.slice_mut().drop(m).take(n - m).set_zero();
    x2.slice_mut().drop(m).take(n - m).put_tbits(&ts[m..n]);
    x2.slice_mut().drop(n).set_zero();
    x2.slice_mut().drop(n).put_tbits(&ts[n..]);
    x2.slice_mut().take(m).set_zero();
    x2.slice_mut().take(m).put_tbits(&ts[..m]);
    assert_eq!(t012, x2);

    let mut x3 = Tbits::<TW>::zero(ts.len());
    t0.slice().copy(&x3.slice_mut().take(m));
    t1.slice().copy(&x3.slice_mut().drop(m).take(n - m));
    t2.slice().copy(&x3.slice_mut().drop(n));
    assert_eq!(t012, x3);
    assert_eq!(ts, &to_tbits(x3.slice())[..]);

    let mut x4 = Tbits::<TW>::zero(ts.len());
    t2.slice().copy(&x4.slice_mut().drop(n));
    t0.slice().copy(&x4.slice_mut().take(m));
    t1.slice().copy(&x4.slice_mut().drop(m).take(n - m));
    assert_eq!(t012, x4);
    assert_eq!(ts, &to_tbits(x4.slice())[..]);

    x4.slice_mut().set_zero();
    t1.slice().copy(&x4.slice_mut().drop(m).take(n - m));
    t2.slice().copy(&x4.slice_mut().drop(n));
    t0.slice().copy(&x4.slice_mut().take(m));
    assert_eq!(t012, x4);
    x4.slice_mut().take(m).set_zero();
    t0.slice().copy(&x4.slice_mut().take(m));
    x4.slice_mut().drop(m).take(n - m).set_zero();
    t1.slice().copy(&x4.slice_mut().drop(m).take(n - m));
    x4.slice_mut().drop(n).set_zero();
    t2.slice().copy(&x4.slice_mut().drop(n));
    assert_eq!(t012, x4);
    x4.slice_mut().drop(m).take(n - m).set_zero();
    t1.slice().copy(&x4.slice_mut().drop(m).take(n - m));
    x4.slice_mut().drop(n).set_zero();
    t2.slice().copy(&x4.slice_mut().drop(n));
    x4.slice_mut().take(m).set_zero();
    t0.slice().copy(&x4.slice_mut().take(m));
    assert_eq!(t012, x4);
    assert_eq!(t0.slice(), x4.slice().take(m));
    assert_eq!(t1.slice(), x4.slice().drop(m).take(n - m));
    assert_eq!(t2.slice(), x4.slice().drop(n));
    assert_eq!(ts, &to_tbits(x4.slice())[..]);
    assert_eq!(ts[..m], to_tbits(x4.slice().take(m))[..]);
    assert_eq!(ts[m..n], to_tbits(x4.slice().drop(m).take(n - m))[..]);
    assert_eq!(ts[n..], to_tbits(x4.slice().drop(n))[..]);
}

pub fn copy_tbits<TW>(ts: &[TW::Tbit])
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display + fmt::Debug,
{
    let s = ts.len();
    for m in 0..(s / 7 * 2 + 1) {
        for n in m..(s / 7 * 5 + 1) {
            for r in n..s {
                copy_range_tbits::<TW>(m, n, &ts[..r]);
            }
        }
    }
}

pub fn add<TW>(a: &Tbits<TW>, b: &Tbits<TW>, ab: &Tbits<TW>)
where
    TW: BasicTbitWord,
{
    let ab1 = a + b;
    assert_eq!(*ab, ab1);
    let aa1 = a + a;
    let bb1 = b + b;
    assert_eq!(ab + b, a + &bb1);
    assert_eq!(a + ab, &aa1 + b);
    assert_eq!(&(a + b) + ab, &(a + b) + &(a + b));

    let mut abba = (*a).clone();
    abba += b;
    assert_eq!(*ab, abba);
    abba += b;
    assert_eq!(ab + b, abba);
    abba += a;
    assert_eq!(&(&(a + b) + b) + a, abba);
}

pub fn get_put_char<TW>(alphabet_str: &str)
where
    TW: StringTbitWord,
{
    let alphabet = Tbits::<TW>::from_str(alphabet_str).unwrap();
    let mut t = Tbits::<TW>::zero(alphabet.size());

    for d in 0..alphabet.size() {
        for n in 0..TW::TBITS_PER_CHAR {
            if d + n >= alphabet.size() {
                break;
            }

            t.set_zero();
            let mut s = t.slice_mut();
            let mut z = alphabet.slice();
            // Copy prefix
            z.advance(d).copy(&s.advance(d));
            // Get & save char
            let ch = z.advance(n).get_char();
            let mut s_ch = s.advance(n);
            // Copy suffix
            z.copy(&s);
            // Put char
            let ok = s_ch.put_char(ch);
            assert!(ok);
            assert_eq!(alphabet, t, "d={}, n={}", d, n);
        }
    }
}

pub fn get_put_usize<TW>(n: usize, min: usize, max: usize)
where
    TW: IntTbitWord,
{
    let mut t = Tbits::<TW>::zero(n);
    for u in min..=max {
        t.slice_mut().put_usize(u);
        let v = t.slice().get_usize();
        assert_eq!(u, v, "n={}", n);
    }
}

pub fn get_put_isize<TW>(n: usize, min: isize, max: isize)
where
    TW: IntTbitWord,
{
    let mut t = Tbits::<TW>::zero(n);
    for i in min..=max {
        t.slice_mut().put_isize(i);
        let v = t.slice().get_isize();
        assert_eq!(i, v, "n={}", n);
    }
}

/*
fn f() {
    let mut ts = Tbits::<TW>::zero(15);
    assert!(ts.slice_mut().from_str("9ANMZ"));
    let s = ts.slice().to_string();
    assert_eq!(s, "9ANMZ");

    let mut tbits = vec![Tbit(0); 15];
    ts.slice().get_tbits(&mut tbits);
    assert_eq!(
        tbits,
        vec![0, 0, 0, 1, 0, 0, 2, 2, 2, 1, 1, 1, 2, 0, 0]
            .into_iter()
            .map(|u| Tbit(u))
            .collect::<Vec<Tbit>>()
    );

    assert_eq!(Trint3(0), Tbits::<TW>::from_str("9").unwrap().slice().get3());
    assert_eq!(Trint3(1), Tbits::<TW>::from_str("A").unwrap().slice().get3());
    assert_eq!(Trint3(2), Tbits::<TW>::from_str("B").unwrap().slice().get3());
    assert_eq!(Trint3(13), Tbits::<TW>::from_str("M").unwrap().slice().get3());
    assert_eq!(Trint3(-13), Tbits::<TW>::from_str("N").unwrap().slice().get3());
    assert_eq!(Trint3(-1), Tbits::<TW>::from_str("Z").unwrap().slice().get3());

    assert_eq!("AAA", Tbits::<TW>::cycle_str(9, "A").to_string());
    assert_eq!("AAAA", Tbits::<TW>::cycle_str(10, "A").to_string());
}

#[test]
fn eq_str() {
    for n in 0..4 {
        let mut t = Tbits::<TW>::zero(n);
        loop {
            let s = t.to_string();
            assert!(Tbits::<TW>::from_str(&s).map_or_else(|_| false, |t| t.eq_str(&s)));
            if !t.inc() {
                break;
            }
        }
    }
}

#[test]
fn mutate() {
    let mut t = Tbits::<TW>::<Tbit> {
        n: 1,
        buf: vec![Tbit(1)],
    };
    let m = t.slice_mut();
    let s = m.as_const();

    // The following definition of slice is refused: mutable borrow occurs.
    //let s = t.slice();

    m.put1(Trint1(1));
    assert_eq!(Trint1(1), s.get1());
    m.put1(Trint1(0));
    assert_eq!(Trint1(0), s.get1());

    // The following line is refused: cannot borrow `t.buf` as mutable more than once at a time.
    //t.buf.push(0);

    assert_eq!(Trint1(0), s.get1());
}

#[test]
fn slices() {
    let a = Tbits::<TW>::from_str("AAA").unwrap();
    let b = Tbits::<TW>::from_str("B").unwrap();
    let c = Tbits::<TW>::from_str("CC").unwrap();
    let abc = Tbits::<TW>::from_slices(&[a.slice(), b.slice(), c.slice()]);
    assert_eq!(abc, Tbits::<TW>::from_str("AAABCC").unwrap());
}
 */

/*
fn str_tbits<TW>(m: usize, n: usize, ts: &[TW::Tbit])
where
    TW: BasicTbitWord,
    TW::Tbit: fmt::Display + fmt::Debug,
{
}
 */
