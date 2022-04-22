use alloc::vec::Vec;
use core::borrow::BorrowMut;

use anyhow::{
    ensure,
    Result,
};
use crypto::{
    keys::x25519,
    signatures::ed25519,
};
use generic_array::{
    typenum::{
        U32,
        U64,
    },
    GenericArray,
};
use rand::{
    distributions::Standard,
    Rng,
};

use crate::{
    core::{
        prng::SpongosRng,
        prp::{
            keccak::KeccakF1600,
            PRP,
        },
    },
    ddml::{
        commands::{
            sizeof,
            unwrap,
            wrap,
            Absorb,
            Commit,
            Ed25519,
            Mask,
            Squeeze,
            X25519,
        },
        modifiers::External,
        types::{
            Bytes,
            Mac,
            NBytes,
            Size,
            Uint8,
        },
    },
};

fn absorb_mask_u8<F>() -> Result<()>
where
    F: PRP,
{
    let mut buf = vec![0_u8; 2];
    let mut tag_wrap = External::new(NBytes::<[u8; 32]>::default());
    let mut tag_unwrap = External::new(NBytes::<[u8; 32]>::default());

    for t in 0_u8..10_u8 {
        let t = Uint8::new(t);
        let buf_size = sizeof::Context::new().absorb(t)?.mask(t)?.size();
        let buf_size2 = sizeof::Context::new().absorb(t)?.mask(t)?.size();
        assert_eq!(buf_size, buf_size2, "Buffer sizes are not equal");
        assert_eq!(buf_size, 2);

        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.commit()?.absorb(t)?.mask(t)?.commit()?.squeeze(&mut tag_wrap)?;
        assert!(
            ctx.stream().is_empty(),
            "Output stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        let mut t2 = Uint8::new(0_u8);
        let mut t3 = Uint8::new(0_u8);
        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.commit()?
            .absorb(&mut t2)?
            .mask(&mut t3)?
            .commit()?
            .squeeze(&mut tag_unwrap)?;
        assert!(
            ctx.stream().is_empty(),
            "Input stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        assert_eq!(t, t2);
        assert_eq!(t, t3);
        assert_eq!(
            tag_wrap, tag_unwrap,
            "Squeezed tag is invalid. Unwrapped tag doesn't match",
        );
    }
    Ok(())
}

#[test]
fn test_u8() {
    assert!(absorb_mask_u8::<KeccakF1600>().is_ok());
}

fn absorb_mask_size<F>() -> Result<()>
where
    F: PRP,
{
    let mut tag_wrap = External::new(NBytes::<GenericArray<u8, U32>>::default());
    let mut tag_unwrap = External::new(NBytes::<GenericArray<u8, U32>>::default());

    let ns = [0, 1, 13, 14, 25, 26, 27, 39, 40, 81, 9840, 9841, 9842, 19683];

    for n in ns.iter() {
        let s = Size::new(*n);
        let buf_size = sizeof::Context::new().absorb(s)?.mask(s)?.size();
        let buf_size2 = sizeof::Context::new().absorb(s)?.mask(s)?.size();
        assert_eq!(buf_size, buf_size2);

        let mut buf = vec![0_u8; buf_size];

        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.commit()?.absorb(s)?.mask(s)?.commit()?.squeeze(&mut tag_wrap)?;
        assert!(
            ctx.stream().is_empty(),
            "Output stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        let mut s2 = Size::default();
        let mut s3 = Size::default();
        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.commit()?
            .absorb(&mut s2)?
            .mask(&mut s3)?
            .commit()?
            .squeeze(&mut tag_unwrap)?;
        assert!(
            ctx.stream().is_empty(),
            "Input stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        assert_eq!(s, s2);
        assert_eq!(s, s3);
        assert_eq!(
            tag_wrap, tag_unwrap,
            "Squeezed tag is invalid. Unwrapped tag doesn't match",
        );
    }
    Ok(())
}

#[test]
fn size() {
    assert!(absorb_mask_size::<KeccakF1600>().is_ok());
}

fn absorb_mask_squeeze_bytes_mac<F>() -> Result<()>
where
    F: PRP,
{
    const NS: [usize; 10] = [0, 3, 255, 256, 257, 483, 486, 489, 1002, 2001];

    let mut tag_wrap = External::new(NBytes::<[u8; 32]>::default());
    let mut tag_unwrap = External::new(NBytes::<[u8; 32]>::default());

    let mut prng = SpongosRng::<F>::new("Spongos tests");
    // TODO: REMOVE
    // let nonce = "TESTPRNGNONCE".as_bytes().to_vec();

    for &n in NS.iter() {
        let ta = Bytes::<Vec<u8>>::new(prng.borrow_mut().sample_iter(Standard).take(n).collect());
        // nonce.slice_mut().inc();
        let nta: NBytes<GenericArray<u8, U64>> = prng.gen();
        // nonce.slice_mut().inc();
        let enta: NBytes<GenericArray<u8, U64>> = prng.gen();
        // nonce.slice_mut().inc();
        let tm = Bytes::<Vec<u8>>::new(prng.borrow_mut().sample_iter(Standard).take(n).collect());
        // nonce.slice_mut().inc();
        let ntm: NBytes<GenericArray<u8, U64>> = prng.gen();
        // nonce.slice_mut().inc();
        let mut ents = External::new(NBytes::<GenericArray<u8, U64>>::default());
        // nonce.slice_mut().inc();
        let mac = Mac::new(n);

        let mut ctx = sizeof::Context::new();
        ctx.commit()?
            .absorb(&ta)?
            .absorb(&nta)?
            .absorb(External::new(&enta))?
            .commit()?
            .mask(&tm)?
            .mask(&ntm)?
            .commit()?
            .squeeze(&ents)?
            .squeeze(&mac)?
            //
            .commit()?
            .squeeze(&tag_wrap)?;
        let buf_size = ctx.size();
        let mut buf = vec![0_u8; buf_size];

        let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
        ctx.commit()?
            .absorb(&ta)?
            .absorb(&nta)?
            .absorb(External::new(&enta))?
            .commit()?
            .mask(&tm)?
            .mask(&ntm)?
            .commit()?
            .squeeze(&mut ents)?
            .squeeze(&mac)?
            //
            .commit()?
            .squeeze(&mut tag_wrap)?;
        assert!(
            ctx.stream().is_empty(),
            "Output stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        let mut ta2 = Bytes::default();
        let mut nta2 = NBytes::<GenericArray<u8, U64>>::default();
        let mut tm2 = Bytes::<Vec<u8>>::default();
        let mut ntm2 = NBytes::<GenericArray<u8, U64>>::default();
        let mut ents2 = External::new(NBytes::<GenericArray<u8, U64>>::default());

        let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
        ctx.commit()?
            .absorb(&mut ta2)?
            .absorb(&mut nta2)?
            .absorb(External::new(&enta))?
            .commit()?
            .mask(&mut tm2)?
            .mask(&mut ntm2)?
            .commit()?
            .squeeze(&mut ents2)?
            .squeeze(&mac)?
            //
            .commit()?
            .squeeze(&mut tag_unwrap)?;
        assert!(
            ctx.stream().is_empty(),
            "Input stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        assert_eq!(ta, ta2, "Error comparing Bytes");
        assert_eq!(nta, nta2, "Error comparing NBytes");
        // ensure!(tm == tm2, "Invalid unwrapped tm value: {:?} != {:?}", tm, tm2);
        // ensure!(ntm == ntm2, "Invalid unwrapped ntm value: {:?} != {:?}", ntm, ntm2);
        // ensure!(ents == ents2, "Invalid unwrapped ents value: {:?} != {:?}", ents, ents2);
        assert_eq!(
            tag_wrap, tag_unwrap,
            "Squeezed tag is invalid. Unwrapped tag doesn't match",
        );
    }

    Ok(())
}

#[test]
fn bytes() {
    assert!(absorb_mask_squeeze_bytes_mac::<KeccakF1600>().is_ok());
}

fn absorb_ed25519<F: PRP>() -> Result<()> {
    let secret = ed25519::SecretKey::from_bytes([7; ed25519::SECRET_KEY_LENGTH]);

    let tag_wrap = Bytes::new([3_u8; 17].to_vec());
    let mut tag_unwrap = Bytes::default();
    let mut hash_wrap = External::new(NBytes::<GenericArray<u8, U64>>::default());
    let mut hash_unwrap = External::new(NBytes::<GenericArray<u8, U64>>::default());

    let mut ctx = sizeof::Context::new();
    ctx.absorb(&tag_wrap)?
        .commit()?
        .squeeze(&hash_wrap)?
        .ed25519(&secret, &hash_wrap)?;
    let buf_size = ctx.size();

    let mut buf = vec![0_u8; buf_size];

    let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
    ctx.absorb(&tag_wrap)?
        .commit()?
        .squeeze(&mut hash_wrap)?
        .ed25519(&secret, &hash_wrap)?;
    assert!(
        ctx.stream().is_empty(),
        "Output stream has not been exhausted. Remaining: {}",
        ctx.stream().len()
    );

    let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
    ctx.absorb(&mut tag_unwrap)?
        .commit()?
        .squeeze(&mut hash_unwrap)?
        .ed25519(&secret.public_key(), &hash_unwrap)?;
    assert!(
        ctx.stream().is_empty(),
        "Input stream has not been exhausted. Remaining: {}",
        ctx.stream().len()
    );

    assert_eq!(
        tag_wrap, tag_unwrap,
        "Squeezed tag is invalid. Unwrapped tag doesn't match",
    );
    assert_eq!(
        hash_wrap, hash_unwrap,
        "Squeezed hash is invalid. Unwrapped hash doesn't match",
    );
    Ok(())
}

#[test]
fn test_ed25519() {
    assert!(absorb_ed25519::<KeccakF1600>().is_ok());
}

// TODO: REMOVE
// fn x25519_static<F>() -> Result<()>
// where
//     F: PRP,
// {
//     let secret_a = x25519::SecretKey::from_bytes([11; 32]);
//     let secret_b = x25519::SecretKey::from_bytes([13; 32]);
//     let mut public_b2 = x25519::PublicKey::from_bytes([0_u8; 32]);

//     let tag_wrap = Bytes::new([3_u8; 17].to_vec());
//     let mut tag_unwrap = Bytes::default();

//     let mut ctx = sizeof::Context::<F>::new();
//     ctx.absorb(&secret_b.public_key())?
//         .x25519(&secret_b, &secret_a.public_key())?
//         .commit()?
//         .mask(&tag_wrap)?;
//     let buf_size = ctx.size();

//     let mut buf = vec![0_u8; buf_size];

//     let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
//     ctx.absorb(&secret_b.public_key())?
//         .x25519(&secret_b, &secret_a.public_key())?
//         .commit()?
//         .mask(&tag_wrap)?;
//     assert!(
//         ctx.stream().is_empty(),
//         "Output stream has not been exhausted. Remaining: {}",
//         ctx.stream().len()
//     );

//     let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
//     ctx.absorb(&mut public_b2)?
//         .x25519(&secret_a, &public_b2)?
//         .commit()?
//         .mask(&mut tag_unwrap)?;
//     assert!(
//         ctx.stream().is_empty(),
//         "Input stream has not been exhausted. Remaining: {}",
//         ctx.stream().len()
//     );

//     assert_eq!(
//         tag_wrap, tag_unwrap,
//         "Squeezed tag is invalid. Unwrapped tag doesn't match",
//     );

//     Ok(())
// }

// fn x25519_ephemeral<F: PRP>() -> Result<()> {
//     let secret_a = x25519::SecretKey::generate_with(&mut SpongosRng::<F>::new("secret_a"));
//     let secret_b = x25519::SecretKey::generate_with(&mut SpongosRng::<F>::new("secret_b"));
//     let mut public_b2 = x25519::PublicKey::from_bytes([0_u8; 32]);

//     let tag_wrap = Bytes::new([3_u8; 17].to_vec());
//     let mut tag_unwrap = Bytes::default();

//     let mut ctx = sizeof::Context::<F>::new();
//     ctx.absorb(&secret_b.public_key())?
//         .x25519(&secret_b, &secret_a.public_key())?
//         .commit()?
//         .mask(&tag_wrap)?;
//     let buf_size = ctx.size();

//     let mut buf = vec![0_u8; buf_size];

//     let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
//     ctx.absorb(&secret_b.public_key())?
//         .x25519(&secret_b, &secret_a.public_key())?
//         .commit()?
//         .mask(&tag_wrap)?;
//     assert!(
//         ctx.stream().is_empty(),
//         "Output stream has not been exhausted. Remaining: {}",
//         ctx.stream().len()
//     );

//     let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
//     ctx.absorb(&mut public_b2)?
//         .x25519(&secret_a, &public_b2)?
//         .commit()?
//         .mask(&mut tag_unwrap)?;
//     assert!(
//         ctx.stream().is_empty(),
//         "Input stream has not been exhausted. Remaining: {}",
//         ctx.stream().len()
//     );

//     assert_eq!(
//         tag_wrap, tag_unwrap,
//         "Squeezed tag is invalid. Unwrapped tag doesn't match",
//     );

//     Ok(())
// }

fn x25519_transport<F: PRP>() -> Result<()> {
    let mut prng = SpongosRng::<F>::new("seed for tests");
    let local_secret_key = x25519::SecretKey::generate_with(&mut prng);
    let remote_secret_key = x25519::SecretKey::generate_with(&mut prng);

    let key_wrap = NBytes::<[u8; 32]>::new(prng.gen());
    let mut key_unwrap = NBytes::<[u8; 32]>::default();

    let mut ctx = sizeof::Context::new();
    ctx.x25519(&local_secret_key.public_key(), &key_wrap)?;
    let buf_size = ctx.size();

    let mut buf = vec![0_u8; buf_size];

    let mut ctx = wrap::Context::<F, &mut [u8]>::new(&mut buf[..]);
    ctx.x25519(&local_secret_key.public_key(), &key_wrap)?;
    assert!(
        ctx.stream().is_empty(),
        "Output stream has not been exhausted. Remaining: {}",
        ctx.stream().len()
    );

    let mut ctx = unwrap::Context::<F, &[u8]>::new(&buf[..]);
    let mut unwrapped_public_key = x25519::PublicKey::from_bytes([0u8; 32]); // Default
    ctx.x25519(&remote_secret_key, &mut key_unwrap)?;
    assert!(
        ctx.stream().is_empty(),
        "Input stream has not been exhausted. Remaining: {}",
        ctx.stream().len()
    );

    assert_eq!(key_wrap, key_unwrap, "X25519 encryption key missmatch");

    Ok(())
}

#[test]
fn test_x25519() {
    // TODO: REMOVE
    // assert!(x25519_static::<KeccakF1600>().is_ok());
    // assert!(x25519_ephemeral::<KeccakF1600>().is_ok());
    assert!(x25519_transport::<KeccakF1600>().is_ok());
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
// assert!(run_join_link()).is_ok());
// }
