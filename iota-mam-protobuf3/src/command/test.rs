use failure::{bail, ensure};
use std::str::FromStr;
use std::convert::{TryInto, TryFrom};

use iota_mam_core::trits::{defs::*, Trits};
use iota_mam_core::prng;
use iota_mam_core::signature::mss;
use iota_mam_core::key_encapsulation::ntru;

use crate::{command::*, types::*, Result};

fn absorb_mask_trint3() -> Result<()> {
    let mut buf = Trits::zero(6);
    let mut tag_wrap = External(NTrytes(Trits::zero(81)));
    let mut tag_unwrap = External(NTrytes(Trits::zero(81)));

    for t in MIN_TRINT3 ..= MAX_TRINT3 {
        let buf_size = sizeof::Context::new().absorb(t)?.mask(t)?.get_size();
        let buf_size2 = sizeof::Context::new().absorb(&t)?.mask(&t)?.get_size();
        ensure!(buf_size == buf_size2, "Buf sizes calcuated by value and by ref do not match.");
        ensure!(buf_size == 6, "Unexpected buf size.");

        {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            ctx
                .commit()?
                .absorb(&t)?
                .mask(&t)?
                .commit()?
                .squeeze(&mut tag_wrap)?
            ;
            ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
        }

        let mut t2 = Trint3::default();
        let mut t3 = Trint3::default();
        {
            let mut ctx = unwrap::Context::new(buf.slice());
            ctx
                .commit()?
                .absorb(&mut t2)?
                .mask(&mut t3)?
                .commit()?
                .squeeze(&mut tag_unwrap)?
            ;
            ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
        }

        ensure!(t == t2);
        ensure!(t == t3);
        ensure!(tag_wrap == tag_unwrap);
    }
    Ok(())
}

fn absorb_mask_size() -> Result<()> {
    let mut tag_wrap = External(NTrytes(Trits::zero(81)));
    let mut tag_unwrap = External(NTrytes(Trits::zero(81)));

    let ns = [
        0,
        1,
        13,
        14,
        25,
        26,
        27,
        39,
        40,
        81,
        9840,
        9841,
        9842,
        19683,
        SIZE_MAX - 1,
        SIZE_MAX,
    ];

    for n in ns.iter() {
        let s = Size(*n);
        let buf_size = sizeof::Context::new().absorb(s)?.mask(s)?.get_size();
        let buf_size2 = sizeof::Context::new().absorb(&s)?.mask(&s)?.get_size();
        ensure!(buf_size == buf_size2, "Buf sizes calcuated by value and by ref do not match.");

        let mut buf = Trits::zero(buf_size);

        {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            ctx
                .commit()?
                .absorb(&s)?
                .mask(&s)?
                .commit()?
                .squeeze(&mut tag_wrap)?
            ;
            ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
        }

        let mut s2 = Size::default();
        let mut s3 = Size::default();
        {
            let mut ctx = unwrap::Context::new(buf.slice());
            ctx
                .commit()?
                .absorb(&mut s2)?
                .mask(&mut s3)?
                .commit()?
                .squeeze(&mut tag_unwrap)?
            ;
            ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
        }

        ensure!(s == s2);
        ensure!(s == s3);
        ensure!(tag_wrap == tag_unwrap);
    }
    Ok(())
}

#[test]
fn trint3() {
    assert!(dbg!(absorb_mask_trint3()).is_ok());
}

#[test]
fn size() {
    assert!(dbg!(absorb_mask_size()).is_ok());
}

fn absorb_mask_squeeze_trytes_mac() -> Result<()> {
    const NS: [usize; 10] = [0, 3, 240, 243, 246, 483, 486, 489, 1002, 2001];

    let mut tag_wrap = External(NTrytes(Trits::zero(81)));
    let mut tag_unwrap = External(NTrytes(Trits::zero(81)));

    let prng = prng::dbg_init_str("TESTPRNGKEY");
    let mut nonce = Trits::from_str("TESTPRNGNONCE").unwrap();

    for n in NS.iter() {
        println!("n={}", n);
        let ta = Trytes(prng.gen_trits(&nonce, *n)); nonce.inc();
        let nta = NTrytes(prng.gen_trits(&nonce, *n)); nonce.inc();
        let enta = External(NTrytes(prng.gen_trits(&nonce, *n))); nonce.inc();
        let tm = Trytes(prng.gen_trits(&nonce, *n)); nonce.inc();
        let ntm = NTrytes(prng.gen_trits(&nonce, *n)); nonce.inc();
        let mut ents = External(NTrytes(Trits::zero(*n))); nonce.inc();
        let mac = Mac(*n);

        let buf_size = {
            let mut ctx = sizeof::Context::new();
            ctx
                .commit()?
                .absorb(&ta)?
                .absorb(&nta)?
                .absorb(&enta)?
                .commit()?
                .mask(&tm)?
                .mask(&ntm)?
                .commit()?
                .squeeze(&ents)?
                .squeeze(&mac)?
                /*
                 */
                .commit()?
                .squeeze(&tag_wrap)?
            ;
            ctx.get_size()
        };
        let mut buf = Trits::zero(dbg!(buf_size));

        {
            let mut ctx = wrap::Context::new(buf.slice_mut());
            ctx
                .commit()?
                .absorb(&ta)?
                .absorb(&nta)?
                .absorb(&enta)?
                .commit()?
                .mask(&tm)?
                .mask(&ntm)?
                .commit()?
                .squeeze(&mut ents)?
                .squeeze(&mac)?
                /*
                 */
                .commit()?
                .squeeze(&mut tag_wrap)?
            ;
            ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
        }

        let mut ta2 = Trytes::default();
        let mut nta2 = NTrytes(Trits::zero(*n));
        let mut tm2 = Trytes::default();
        let mut ntm2 = NTrytes(Trits::zero(*n));
        let mut ents2 = External(NTrytes(Trits::zero(*n)));
        {
            let mut ctx = unwrap::Context::new(buf.slice());
            ctx
                .commit()?
                .absorb(&mut ta2)?
                .absorb(&mut nta2)?
                .absorb(&enta)?
                .commit()?
                .mask(&mut tm2)?
                .mask(&mut ntm2)?
                .commit()?
                .squeeze(&mut ents2)?
                .squeeze(&mac)?
                /*
                 */
                .commit()?
                .squeeze(&mut tag_unwrap)?
            ;
            ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
        }

        ensure!(ta == ta2);
        ensure!(nta == nta2);
        ensure!(tm == tm2);
        ensure!(ntm == ntm2);
        ensure!(ents == ents2);
        ensure!(tag_wrap == tag_unwrap);
    }

    Ok(())
}

#[test]
fn trytes() {
    assert!(dbg!(absorb_mask_squeeze_trytes_mac()).is_ok());
}

fn mssig_traverse() -> Result<()> {
    let payload = Trytes(Trits::cycle_str(123, "PAYLOAD"));
    let mut hash = External(NTrytes(Trits::zero(mss::HASH_SIZE)));
    let prng = prng::dbg_init_str("TESTPRNGKEY");
    let n = Trits::zero(33);
    let mut apk = mss::PublicKey::default();

    for d in 0..2 {
        let mut sk = mss::PrivateKey::gen(&prng, n.slice(), d);

        loop {
            let buf_size = {
                let mut ctx = sizeof::Context::new();
                ctx
                    .absorb(&payload)?
                    .commit()?
                    .squeeze(&hash)?
                    .commit()?
                    .mssig(&sk, &hash)?
                    .mssig(&sk, MssHashSig)?
                ;
                ctx.get_size()
            };

            let mut buf = Trits::zero(dbg!(buf_size));
            {
                let mut ctx = wrap::Context::new(buf.slice_mut());
                ctx
                    .absorb(&payload)?
                    .commit()?
                    .squeeze(&mut hash)?
                    .commit()?
                    .mssig(&sk, &hash)?
                    .mssig(&mut sk, MssHashSig)?
                ;
                ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
            }
            let mut payload2 = Trytes::default();
            {
                let mut ctx = unwrap::Context::new(buf.slice());
                ctx
                    .absorb(&mut payload2)?
                    .commit()?
                    .squeeze(&mut hash)?
                    .commit()?
                    .mssig(&mut apk, &hash)?
                    .mssig(sk.public_key(), MssHashSig)?
                ;
                ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
                ensure!(payload == payload2, "Absorbed bad payload.");
                ensure!(&apk == sk.public_key(), "Recovered bad key.");
            }

            if 0 == sk.skn_left() {
                break;
            }
        }
    }
    Ok(())
}

#[test]
fn mssig() {
    assert!(dbg!(mssig_traverse()).is_ok());
}

fn ntrukem_caps() -> Result<()> {
    let prng = prng::dbg_init_str("TESTPRNGKEY");
    let nonce = Trits::zero(15);
    let (sk, pk) = ntru::gen(&prng, nonce.slice());

    let payload = Trytes(Trits::cycle_str(123, "PAYLOAD"));
    let key = NTrytes(prng.gen_trits(&nonce, ntru::KEY_SIZE));

    let buf_size = {
        let mut ctx = sizeof::Context::new();
        ctx
            .absorb(&payload)?
            .commit()?
            .ntrukem(&pk, &key)?
        ;
        ctx.get_size()
    };
    let mut buf = Trits::zero(buf_size);
    {
        let mut ctx = wrap::Context::new(buf.slice_mut());
        ctx
            .absorb(&payload)?
            .commit()?
            .ntrukem((&pk, &prng, &nonce), &key)?
        ;
        ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
    }
    let mut payload2 = Trytes::default();
    let mut key2 = NTrytes(Trits::zero(ntru::KEY_SIZE));
    {
        let mut ctx = unwrap::Context::new(buf.slice());
        ctx
            .absorb(&mut payload2)?
            .commit()?
            .ntrukem(&sk, &mut key2)?
        ;
        ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
    }
    ensure!(key == key2, "Secret and decapsulated secret differ.");
    Ok(())
}

#[test]
fn ntrukem() {
    assert!(dbg!(ntrukem_caps()).is_ok());
}

use crate::io;
use iota_mam_core::spongos::{self, Spongos};
use std::convert::{From, Into, AsRef};

#[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
struct TestRelLink(Trint3);
#[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
struct TestAbsLink(Trint3, TestRelLink);

impl AbsorbFallback for TestAbsLink {
    fn sizeof_absorb(&self, ctx: &mut sizeof::Context) -> Result<()> {
        ctx.absorb(&self.0)?.absorb(&(self.1).0)?;
        Ok(())
    }
    fn wrap_absorb<OS: io::OStream>(&self, ctx: &mut wrap::Context<OS>) -> Result<()> {
        ctx.absorb(&self.0)?.absorb(&(self.1).0)?;
        Ok(())
    }
    fn unwrap_absorb<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()> {
        ctx.absorb(&mut self.0)?.absorb(&mut (self.1).0)?;
        Ok(())
    }
}
impl SkipFallback for TestRelLink {
    fn sizeof_skip(&self, ctx: &mut sizeof::Context) -> Result<()> {
        ctx.skip(&self.0)?;
        Ok(())
    }
    fn wrap_skip<OS: io::OStream>(&self, ctx: &mut wrap::Context<OS>) -> Result<()> {
        ctx.skip(&self.0)?;
        Ok(())
    }
    fn unwrap_skip<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()> {
        ctx.skip(&mut self.0)?;
        Ok(())
    }
}

impl From<TestAbsLink> for TestRelLink {
    fn from(a: TestAbsLink) -> TestRelLink {
        a.1
    }
}
impl AsRef<TestRelLink> for TestAbsLink {
    fn as_ref(&self) -> &TestRelLink {
        &self.1
    }
}

struct TestStore<Link, Info> {
    cell1: Option<(Link, (spongos::Inner, Info))>,
    cell2: Option<(Link, (spongos::Inner, Info))>,
    cell3: Option<(Link, (spongos::Inner, Info))>,
}
impl<Link, Info> TestStore<Link, Info> {
    fn new() -> Self {
        Self {
            cell1: None,
            cell2: None,
            cell3: None,
        }
    }
}

impl<Link: PartialEq + Clone, Info: Clone> LinkStore<Link> for TestStore<Link, Info> {
    type Info = Info;
    fn lookup(&self, l: &Link) -> Result<(Spongos, Self::Info)> {
        if let Some((l,(s,i))) = &self.cell1 {
            if l == l {
                return Ok((s.into(), i.clone()));
            }
        }
        if let Some((l,(s,i))) = &self.cell2 {
            if l == l {
                return Ok((s.into(), i.clone()));
            }
        }
        if let Some((l,(s,i))) = &self.cell3 {
            if l == l {
                return Ok((s.into(), i.clone()));
            }
        }
        bail!("Link not found");
    }
    fn update(&mut self, l: &Link, s: Spongos, i: Self::Info) -> Result<()> {
        if let None = &self.cell1 {
            self.cell1 = Some((l.clone(), (s.try_into().unwrap(), i)));
            Ok(())
        } else
        if let None = &self.cell2 {
            self.cell2 = Some((l.clone(), (s.try_into().unwrap(), i)));
            Ok(())
        } else
        if let None = &self.cell3 {
            self.cell3 = Some((l.clone(), (s.try_into().unwrap(), i)));
            Ok(())
        } else {
            bail!("Link store is full");
        }
    }
    fn erase(&mut self, l: &Link) {
        if let Some(lsi) = &self.cell1 {
            if lsi.0 == *l {
                self.cell1 = None;
            }
        }
        if let Some(lsi) = &self.cell2 {
            if lsi.0 == *l {
                self.cell2 = None;
            }
        }
        if let Some(lsi) = &self.cell3 {
            if lsi.0 == *l {
                self.cell3 = None;
            }
        }
    }
}

#[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
struct TestMessageInfo;
#[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
struct TestMessage<AbsLink, RelLink> {
    addr: AbsLink,
    link: RelLink,
    masked: Trint3,
}

/*
struct WrapCtx<L, S, OS> where
    L: Link, S: LinkStore<L>, OS: io::OStream,
{
    ss: wrap::Context<OS>,
    store: S,
}
*/

impl<AbsLink, RelLink> TestMessage<AbsLink, RelLink> where
    AbsLink: AbsorbFallback + AsRef<RelLink>,
    RelLink: SkipFallback,
{
    fn size<S: LinkStore<RelLink>>(&self, store: &S) -> Result<usize> {
        let mut ctx = sizeof::Context::new();
        ctx
            .absorb(&self.addr)?
            .join(store, &self.link)?
            .mask(&self.masked)?
        ;
        Ok(0)
    }
    fn wrap<S: LinkStore<RelLink>, OS: io::OStream>(&self, store: &mut S, ctx: &mut wrap::Context<OS>, i: <S as LinkStore<RelLink>>::Info) -> Result<()> {
        ctx
            .absorb(&self.addr)?
            .join(store, &self.link)?
            .mask(&self.masked)?
        ;
        let mut spongos = ctx.spongos.fork();
        spongos.commit();
        store.update(self.addr.as_ref(), spongos, i)?;
        Ok(())
    }
    fn unwrap<S: LinkStore<RelLink>, IS: io::IStream>(&mut self, store: &S, ctx: &mut unwrap::Context<IS>) -> Result<()> {
        ctx
            .absorb(&mut self.addr)?
            .join(store, &mut self.link)?
            .mask(&mut self.masked)?
        ;
        Ok(())
    }
}

#[test]
fn join_link() {
    let msg = TestMessage::<TestAbsLink, TestRelLink> {
        addr: TestAbsLink(Trint3(1), TestRelLink(Trint3(2))),
        link: TestRelLink(Trint3(3)),
        masked: Trint3(4),
    };
    let mut store = TestStore::new();

    let buf_size = msg.size(&store).unwrap();
    let mut buf = Trits::zero(buf_size);

    {
        let mut wrap_ctx = wrap::Context::new(buf.slice_mut());
        let i = TestMessageInfo;
        msg.wrap(&mut store, &mut wrap_ctx, i);
        assert!(wrap_ctx.stream.is_empty());
    }

    let mut msg2 = TestMessage::<TestAbsLink, TestRelLink>::default();
    {
        let mut unwrap_ctx = unwrap::Context::new(buf.slice());
        msg2.unwrap(&store, &mut unwrap_ctx);
        assert!(unwrap_ctx.stream.is_empty());
    }

    assert_eq!(msg, msg2);
}
