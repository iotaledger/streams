use anyhow::{
    ensure,
    Result,
};
use std::str::FromStr;

use iota_streams_core::{
    prng,
    sponge::{
        prp::PRP,
        spongos::Spongos,
    },
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};
use iota_streams_core_keccak::sponge::prp::keccak::KeccakF1600;

use crate::{
    command::*,
    types::*,
};

fn absorb_mask_u8<F: PRP>() -> Result<()> {
    let mut buf = vec![0_u8; 2];
    let mut tag_wrap = External(NBytes(vec![0; 32]));
    let mut tag_unwrap = External(NBytes(vec![0; 32]));

    for t in 0_u8..10_u8 {
        let t = Uint8(t);
        let buf_size = sizeof::Context::<F>::new().absorb(t)?.mask(t)?.get_size();
        let buf_size2 = sizeof::Context::<F>::new().absorb(&t)?.mask(&t)?.get_size();
        ensure!(
            buf_size == buf_size2,
            "Buf sizes calcuated by value and by ref do not match."
        );
        ensure!(buf_size == 2, "Unexpected buf size: {} != 2.", buf_size);

        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
            ctx.commit()?.absorb(&t)?.mask(&t)?.commit()?.squeeze(&mut tag_wrap)?;
            ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
        }

        let mut t2 = Uint8(0_u8);
        let mut t3 = Uint8(0_u8);
        {
            let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
            ctx.commit()?
                .absorb(&mut t2)?
                .mask(&mut t3)?
                .commit()?
                .squeeze(&mut tag_unwrap)?;
            ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
        }

        ensure!(t == t2, "Invalid unmasked u8 value");
        ensure!(t == t3, "Invalid unmasked u8 value");
        ensure!(tag_wrap == tag_unwrap, "Invalid squeezed tags");
    }
    Ok(())
}

#[test]
fn test_u8() {
    assert!(dbg!(absorb_mask_u8::<KeccakF1600>()).is_ok());
}

fn absorb_mask_size<F: PRP>() -> Result<()> {
    let mut tag_wrap = External(NBytes(vec![0_u8; 32]));
    let mut tag_unwrap = External(NBytes(vec![0_u8; 32]));

    let ns = [0, 1, 13, 14, 25, 26, 27, 39, 40, 81, 9840, 9841, 9842, 19683];

    for n in ns.iter() {
        let s = Size(*n);
        let buf_size = sizeof::Context::<F>::new().absorb(s)?.mask(s)?.get_size();
        let buf_size2 = sizeof::Context::<F>::new().absorb(&s)?.mask(&s)?.get_size();
        ensure!(
            buf_size == buf_size2,
            "Buf sizes calcuated by value and by ref do not match."
        );

        let mut buf = vec![0_u8; buf_size];

        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
            ctx.commit()?.absorb(&s)?.mask(&s)?.commit()?.squeeze(&mut tag_wrap)?;
            ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
        }

        let mut s2 = Size::default();
        let mut s3 = Size::default();
        {
            let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
            ctx.commit()?
                .absorb(&mut s2)?
                .mask(&mut s3)?
                .commit()?
                .squeeze(&mut tag_unwrap)?;
            ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
        }

        ensure!(s == s2, "Invalid unwrapped size value: {} != {}", s, s2);
        ensure!(s == s3, "Invalid unwrapped size value: {} != {}", s, s3);
        ensure!(tag_wrap == tag_unwrap, "Invalid squeezed value");
    }
    Ok(())
}

#[test]
fn size() {
    assert!(dbg!(absorb_mask_size::<KeccakF1600>()).is_ok());
}

fn absorb_mask_squeeze_bytes_mac<F: PRP>() -> Result<()> {
    const NS: [usize; 10] = [0, 3, 255, 256, 257, 483, 486, 489, 1002, 2001];

    let mut tag_wrap = External(NBytes(vec![0_u8; 32]));
    let mut tag_unwrap = External(NBytes(vec![0_u8; 32]));

    let prng = prng::dbg_init_str::<F>("TESTPRNGKEY");
    let mut nonce = "TESTPRNGNONCE".as_bytes().to_vec();

    for n in NS.iter() {
        let ta = Bytes(prng.gen_bytes(&nonce, *n));
        // nonce.slice_mut().inc();
        let nta = NBytes(prng.gen_bytes(&nonce, *n));
        // nonce.slice_mut().inc();
        let enta = NBytes(prng.gen_bytes(&nonce, *n));
        // nonce.slice_mut().inc();
        let tm = Bytes(prng.gen_bytes(&nonce, *n));
        // nonce.slice_mut().inc();
        let ntm = NBytes(prng.gen_bytes(&nonce, *n));
        // nonce.slice_mut().inc();
        let mut ents = External(NBytes(vec![0; *n]));
        // nonce.slice_mut().inc();
        let mac = Mac(*n);

        let buf_size = {
            let mut ctx = sizeof::Context::<F>::new();
            ctx.commit()?
                .absorb(&ta)?
                .absorb(&nta)?
                .absorb(External(&enta))?
                .commit()?
                .mask(&tm)?
                .mask(&ntm)?
                .commit()?
                .squeeze(&ents)?
                .squeeze(&mac)?
                //
                .commit()?
                .squeeze(&tag_wrap)?;
            ctx.get_size()
        };
        let mut buf = vec![0_u8; buf_size];

        {
            let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
            ctx.commit()?
                .absorb(&ta)?
                .absorb(&nta)?
                .absorb(External(&enta))?
                .commit()?
                .mask(&tm)?
                .mask(&ntm)?
                .commit()?
                .squeeze(&mut ents)?
                .squeeze(&mac)?
                //
                .commit()?
                .squeeze(&mut tag_wrap)?;
            ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
        }

        let mut ta2 = Bytes::default();
        let mut nta2 = NBytes(vec![0_u8; *n]);
        let mut tm2 = Bytes::default();
        let mut ntm2 = NBytes(vec![0_u8; *n]);
        let mut ents2 = External(NBytes(vec![0_u8; *n]));
        {
            let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
            ctx.commit()?
                .absorb(&mut ta2)?
                .absorb(&mut nta2)?
                .absorb(External(&enta))?
                .commit()?
                .mask(&mut tm2)?
                .mask(&mut ntm2)?
                .commit()?
                .squeeze(&mut ents2)?
                .squeeze(&mac)?
                //
                .commit()?
                .squeeze(&mut tag_unwrap)?;
            ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
        }

        ensure!(ta == ta2, "Invalid unwrapped ta value: {:?} != {:?}", ta, ta2);
        ensure!(nta == nta2, "Invalid unwrapped nta value: {:?} != {:?}", nta, nta2);
        // ensure!(tm == tm2, "Invalid unwrapped tm value: {:?} != {:?}", tm, tm2);
        // ensure!(ntm == ntm2, "Invalid unwrapped ntm value: {:?} != {:?}", ntm, ntm2);
        // ensure!(ents == ents2, "Invalid unwrapped ents value: {:?} != {:?}", ents, ents2);
        ensure!(
            tag_wrap == tag_unwrap,
            "Invalid squeezed tag value: {:?} != {:?}",
            tag_wrap,
            tag_unwrap
        );
    }

    Ok(())
}

#[test]
fn bytes() {
    assert!(dbg!(absorb_mask_squeeze_bytes_mac::<KeccakF1600>()).is_ok());
}

fn absorb_ed25519<F: PRP>() -> Result<()> {
    let secret = ed25519::SecretKey::from_bytes(&[7; ed25519::SECRET_KEY_LENGTH]).unwrap();
    let public = ed25519::PublicKey::from(&secret);
    let kp = ed25519::Keypair { secret, public };

    let ta = Bytes([3_u8; 17].to_vec());
    let mut uta = Bytes(Vec::new());
    let mut hash = External(NBytes(vec![0_u8; 64]));
    let mut uhash = External(NBytes(vec![0_u8; 64]));

    let buf_size = {
        let mut ctx = sizeof::Context::<F>::new();
        ctx.absorb(&ta)?
            .commit()?
            .squeeze(&hash)?
            .ed25519(&kp, &hash)?
            .ed25519(&kp, HashSig)?;
        ctx.get_size()
    };

    let mut buf = vec![0_u8; buf_size];

    {
        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.absorb(&ta)?
            .commit()?
            .squeeze(&mut hash)?
            .ed25519(&kp, &hash)?
            .ed25519(&kp, HashSig)?;
        ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
    }

    {
        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.absorb(&mut uta)?
            .commit()?
            .squeeze(&mut uhash)?
            .ed25519(&public, &uhash)?
            .ed25519(&public, HashSig)?;
        ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
    }

    ensure!(ta == uta, "Invalid unwrapped ta value: {:?} != {:?}", ta, uta);
    ensure!(hash == uhash, "Invalid unwrapped hash value: {:?} != {:?}", hash, uhash);

    Ok(())
}

#[test]
fn test_ed25519() {
    assert!(dbg!(absorb_ed25519::<KeccakF1600>()).is_ok());
}

fn x25519_static<F: PRP>() -> Result<()> {
    let secret_a = x25519::StaticSecret::from([11; 32]);
    let secret_b = x25519::StaticSecret::from([13; 32]);
    let public_a = x25519::PublicKey::from(&secret_a);
    let public_b = x25519::PublicKey::from(&secret_b);
    let mut public_b2 = x25519::PublicKey::from([0_u8; 32]);

    let ta = Bytes([3_u8; 17].to_vec());
    let mut uta = Bytes(Vec::new());

    let buf_size = {
        let mut ctx = sizeof::Context::<F>::new();
        ctx.absorb(&public_b)?
            .x25519(&secret_b, &public_a)?
            .commit()?
            .mask(&ta)?;
        ctx.get_size()
    };

    let mut buf = vec![0_u8; buf_size];

    {
        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.absorb(&public_b)?
            .x25519(&secret_b, &public_a)?
            .commit()?
            .mask(&ta)?;
        ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
    }

    {
        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.absorb(&mut public_b2)?
            .x25519(&secret_a, &public_b2)?
            .commit()?
            .mask(&mut uta)?;
        ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
    }

    ensure!(ta == uta, "Invalid unwrapped ta value: {:?} != {:?}", ta, uta);

    Ok(())
}

fn x25519_ephemeral<F: PRP>() -> Result<()> {
    let secret_a = x25519::EphemeralSecret::new(&mut rand::thread_rng());
    let secret_b = x25519::EphemeralSecret::new(&mut rand::thread_rng());
    let public_a = x25519::PublicKey::from(&secret_a);
    let public_b = x25519::PublicKey::from(&secret_b);
    let mut public_b2 = x25519::PublicKey::from([0_u8; 32]);

    let ta = Bytes([3_u8; 17].to_vec());
    let mut uta = Bytes(Vec::new());

    let buf_size = {
        let mut ctx = sizeof::Context::<F>::new();
        ctx.absorb(&public_b)?
            .x25519(&secret_b, &public_a)?
            .commit()?
            .mask(&ta)?;
        ctx.get_size()
    };

    let mut buf = vec![0_u8; buf_size];

    {
        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.absorb(&public_b)?
            .x25519(secret_b, &public_a)?
            .commit()?
            .mask(&ta)?;
        ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
    }

    {
        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.absorb(&mut public_b2)?
            .x25519(secret_a, &public_b2)?
            .commit()?
            .mask(&mut uta)?;
        ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
    }

    ensure!(ta == uta, "Invalid unwrapped ta value: {:?} != {:?}", ta, uta);

    Ok(())
}

fn x25519_transport<F: PRP>() -> Result<()> {
    let secret_a = x25519::StaticSecret::new(&mut rand::thread_rng());
    let public_a = x25519::PublicKey::from(&secret_a);

    let key = NBytes(vec![3_u8; 32]);
    let mut ukey = NBytes(vec![0_u8; 32]);

    let buf_size = {
        let mut ctx = sizeof::Context::<F>::new();
        ctx.x25519(&public_a, &key)?;
        ctx.get_size()
    };

    let mut buf = vec![0_u8; buf_size];

    {
        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.x25519(&public_a, &key)?;
        ensure!(ctx.stream.is_empty(), "Output stream is not exhausted.");
    }

    {
        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.x25519(&secret_a, &mut ukey)?;
        ensure!(ctx.stream.is_empty(), "Input stream is not exhausted.");
    }

    ensure!(key == ukey, "Invalid unwrapped key value: {:?} != {:?}", key, ukey);

    Ok(())
}

#[test]
fn test_x25519() {
    assert!(dbg!(x25519_static::<KeccakF1600>()).is_ok());
    assert!(dbg!(x25519_ephemeral::<KeccakF1600>()).is_ok());
    assert!(dbg!(x25519_transport::<KeccakF1600>()).is_ok());
}

// use crate::io;
// use iota_streams_core::sponge::spongos::{self, Spongos};
// use std::convert::{AsRef, From, Into};
//
// #[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
// struct TestRelLink(Trint3);
// #[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
// struct TestAbsLink(Trint3, TestRelLink);
//
// impl AbsorbFallback for TestAbsLink {
// fn sizeof_absorb(&self, ctx: &mut sizeof::Context::<F>) -> Result<()> {
// ctx.absorb(&self.0)?.absorb(&(self.1).0)?;
// Ok(())
// }
// fn wrap_absorb<OS: io::OStream>(&self, ctx: &mut wrap::Context<OS>) -> Result<()> {
// ctx.absorb(&self.0)?.absorb(&(self.1).0)?;
// Ok(())
// }
// fn unwrap_absorb<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()> {
// ctx.absorb(&mut self.0)?.absorb(&mut (self.1).0)?;
// Ok(())
// }
// }
// impl SkipFallback for TestRelLink {
// fn sizeof_skip(&self, ctx: &mut sizeof::Context::<F>) -> Result<()> {
// ctx.skip(&self.0)?;
// Ok(())
// }
// fn wrap_skip<OS: io::OStream>(&self, ctx: &mut wrap::Context<OS>) -> Result<()> {
// ctx.skip(&self.0)?;
// Ok(())
// }
// fn unwrap_skip<IS: io::IStream>(&mut self, ctx: &mut unwrap::Context<IS>) -> Result<()> {
// ctx.skip(&mut self.0)?;
// Ok(())
// }
// }
//
// impl From<TestAbsLink> for TestRelLink {
// fn from(a: TestAbsLink) -> TestRelLink {
// a.1
// }
// }
// impl AsRef<TestRelLink> for TestAbsLink {
// fn as_ref(&self) -> &TestRelLink {
// &self.1
// }
// }
//
// struct TestStore<Link, Info> {
// cell1: Option<(Link, (spongos::Inner, Info))>,
// cell2: Option<(Link, (spongos::Inner, Info))>,
// cell3: Option<(Link, (spongos::Inner, Info))>,
// }
// impl<Link, Info> TestStore<Link, Info> {
// fn new() -> Self {
// Self {
// cell1: None,
// cell2: None,
// cell3: None,
// }
// }
// }
//
// impl<Link: PartialEq + Clone, Info: Clone> LinkStore<Link> for TestStore<Link, Info> {
// type Info = Info;
// fn lookup(&self, link: &Link) -> Result<(Spongos, Self::Info)> {
// if let Some((l, (s, i))) = &self.cell1 {
// if link == l {
// return Ok((s.into(), i.clone()));
// }
// }
// if let Some((l, (s, i))) = &self.cell2 {
// if link == l {
// return Ok((s.into(), i.clone()));
// }
// }
// if let Some((l, (s, i))) = &self.cell3 {
// if link == l {
// return Ok((s.into(), i.clone()));
// }
// }
// bail!("Link not found");
// }
// fn update(&mut self, l: &Link, s: Spongos, i: Self::Info) -> Result<()> {
// if let None = &self.cell1 {
// self.cell1 = Some((l.clone(), (s.try_into().unwrap(), i)));
// Ok(())
// } else if let None = &self.cell2 {
// self.cell2 = Some((l.clone(), (s.try_into().unwrap(), i)));
// Ok(())
// } else if let None = &self.cell3 {
// self.cell3 = Some((l.clone(), (s.try_into().unwrap(), i)));
// Ok(())
// } else {
// bail!("Link store is full");
// }
// }
// fn erase(&mut self, l: &Link) {
// if let Some(lsi) = &self.cell1 {
// if lsi.0 == *l {
// self.cell1 = None;
// }
// }
// if let Some(lsi) = &self.cell2 {
// if lsi.0 == *l {
// self.cell2 = None;
// }
// }
// if let Some(lsi) = &self.cell3 {
// if lsi.0 == *l {
// self.cell3 = None;
// }
// }
// }
// }
//
// #[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
// struct TestMessageInfo(usize);
// #[derive(PartialEq, Eq, Copy, Clone, Default, Debug)]
// struct TestMessage<AbsLink, RelLink> {
// addr: AbsLink,
// link: RelLink,
// masked: Trint3,
// }
//
//
// struct WrapCtx<L, S, OS> where
// L: Link, S: LinkStore<L>, OS: io::OStream,
// {
// ss: wrap::Context<OS>,
// store: S,
// }
// /
//
// impl<AbsLink, RelLink> TestMessage<AbsLink, RelLink>
// where
// AbsLink: AbsorbFallback + AsRef<RelLink>,
// RelLink: SkipFallback,
// {
// fn size<S: LinkStore<RelLink>>(&self, store: &S) -> Result<usize> {
// let mut ctx = sizeof::Context::<F>::new();
// ctx.absorb(&self.addr)?
// .join(store, &self.link)?
// .mask(&self.masked)?;
// Ok(ctx.get_size())
// }
// fn wrap<S: LinkStore<RelLink>, OS: io::OStream>(
// &self,
// store: &mut S,
// ctx: &mut wrap::Context<OS>,
// i: <S as LinkStore<RelLink>>::Info,
// ) -> Result<()> {
// ctx.absorb(&self.addr)?
// .join(store, &self.link)?
// .mask(&self.masked)?;
// let mut spongos = ctx.spongos.fork();
// spongos.commit();
// store.update(self.addr.as_ref(), spongos, i)?;
// Ok(())
// }
// fn unwrap<S: LinkStore<RelLink>, IS: io::IStream>(
// &mut self,
// store: &S,
// ctx: &mut unwrap::Context<IS>,
// ) -> Result<()> {
// ctx.absorb(&mut self.addr)?
// .join(store, &mut self.link)?
// .mask(&mut self.masked)?;
// Ok(())
// }
// }
//
// fn run_join_link() -> Result<()> {
// let msg = TestMessage::<TestAbsLink, TestRelLink> {
// addr: TestAbsLink(Trint3(1), TestRelLink(Trint3(2))),
// link: TestRelLink(Trint3(3)),
// masked: Trint3(4),
// };
// let mut store = TestStore::new();
// store.update(&TestRelLink(Trint3(3)), Spongos::init(), TestMessageInfo(0))?;
//
// let buf_size = msg.size(&store).unwrap();
// let mut buf = Tbits::zero(buf_size);
//
// {
// let mut wrap_ctx = wrap::Context::<F, TbitSliceMut<TW>>::new(buf.slice_mut());
// let i = TestMessageInfo(1);
// msg.wrap(&mut store, &mut wrap_ctx, i)?;
// ensure!(wrap_ctx.stream.is_empty());
// }
//
// let mut msg2 = TestMessage::<TestAbsLink, TestRelLink>::default();
// {
// let mut unwrap_ctx = unwrap::Context::<F, TbitSlice<TW>>::new(buf.slice());
// TODO: unwrap and check.
// msg2.unwrap(&store, &mut unwrap_ctx)?;
// ensure!(unwrap_ctx.stream.is_empty());
// }
//
// ensure!(msg == msg2);
// Ok(())
// }
//
// #[test]
// fn join_link() {
// assert!(dbg!(run_join_link()).is_ok());
// }
