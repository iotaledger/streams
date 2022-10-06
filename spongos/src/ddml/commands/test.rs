use alloc::vec::Vec;
use core::borrow::BorrowMut;

use crypto::{keys::x25519, signatures::ed25519};
use generic_array::{typenum::U64, GenericArray};
use rand::{distributions::Standard, Rng};

use crate::{
    core::{
        prng::SpongosRng,
        prp::{keccak::KeccakF1600, PRP},
    },
    ddml::{
        commands::{sizeof, unwrap, wrap, Absorb, Commit, Ed25519, Mask, Squeeze, X25519},
        modifiers::External,
        types::{Bytes, Mac, NBytes, Size, Uint8},
    },
    error::Result,
};

fn absorb_mask_u8<F>() -> Result<()>
where
    F: PRP + Default,
{
    let mut buf = vec![0u8; 2];
    let mut tag_wrap = [0; 32];
    let mut tag_unwrap = [0; 32];

    for t in 0u8..10u8 {
        let t = Uint8::new(t);
        let buf_size = sizeof::Context::new().absorb(t)?.mask(t)?.finalize();
        let buf_size2 = sizeof::Context::new().absorb(t)?.mask(t)?.finalize();
        assert_eq!(buf_size, buf_size2, "Buffer sizes are not equal");
        assert_eq!(buf_size, 2);

        let mut ctx = wrap::Context::<&mut [u8], F>::new(&mut buf[..]);
        ctx.commit()?
            .absorb(t)?
            .mask(t)?
            .commit()?
            .squeeze(External::new(&mut NBytes::new(&mut tag_wrap)))?;
        assert!(
            ctx.stream().is_empty(),
            "Output stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        let mut t2 = Uint8::new(0u8);
        let mut t3 = Uint8::new(0u8);
        let mut ctx = unwrap::Context::<&[u8], F>::new(&buf[..]);
        ctx.commit()?
            .absorb(&mut t2)?
            .mask(&mut t3)?
            .commit()?
            .squeeze(External::new(&mut NBytes::new(&mut tag_unwrap)))?;
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
    F: PRP + Default,
{
    let mut tag_wrap = [0; 32];
    let mut tag_unwrap = [0; 32];

    let ns = [0, 1, 13, 14, 25, 26, 27, 39, 40, 81, 9840, 9841, 9842, 19683];

    for n in ns.iter() {
        let s = Size::new(*n);
        let buf_size = sizeof::Context::new().absorb(s)?.mask(s)?.finalize();
        let buf_size2 = sizeof::Context::new().absorb(s)?.mask(s)?.finalize();
        assert_eq!(buf_size, buf_size2);

        let mut buf = vec![0u8; buf_size];

        let mut ctx = wrap::Context::<_, F>::new(&mut buf[..]);
        ctx.commit()?
            .absorb(s)?
            .mask(s)?
            .commit()?
            .squeeze(External::new(&mut NBytes::new(&mut tag_wrap)))?;
        assert!(
            ctx.stream().is_empty(),
            "Output stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        let mut s2 = Size::default();
        let mut s3 = Size::default();
        let mut ctx = unwrap::Context::<_, F>::new(&buf[..]);
        ctx.commit()?
            .absorb(&mut s2)?
            .mask(&mut s3)?
            .commit()?
            .squeeze(External::new(&mut NBytes::new(&mut tag_unwrap)))?;
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
    F: PRP + Default,
{
    const NS: [usize; 10] = [0, 3, 255, 256, 257, 483, 486, 489, 1002, 2001];

    let mut tag_wrap = [0; 32];
    let mut tag_unwrap = [0; 32];

    let mut prng = SpongosRng::<F>::new("Spongos tests");

    for &n in NS.iter() {
        let ta: Bytes = prng.borrow_mut().sample_iter(Standard).take(n).collect();
        let nta: NBytes<GenericArray<u8, U64>> = prng.gen();
        let enta: External<NBytes<GenericArray<u8, U64>>> = External::new(prng.gen());
        let tm: Bytes = prng.borrow_mut().sample_iter(Standard).take(n).collect();
        let ntm: NBytes<GenericArray<u8, U64>> = prng.gen();
        let mut ents = External::new(NBytes::new([0; 64]));
        let mac = Mac::new(n);

        let mut ctx = sizeof::Context::new();
        ctx.commit()?
            .absorb(ta.as_ref())?
            .absorb(nta.as_ref())?
            .absorb(enta.as_ref())?
            .commit()?
            .mask(tm.as_ref())?
            .mask(ntm.as_ref())?
            .commit()?
            .squeeze(ents.as_ref())?
            .squeeze(&mac)?
            .commit()?
            .squeeze(External::new(&NBytes::new(tag_wrap)))?;
        let buf_size = ctx.finalize();
        let mut buf = vec![0u8; buf_size];

        let mut ctx = wrap::Context::<_, F>::new(&mut buf[..]);
        ctx.commit()?
            .absorb(ta.as_ref())?
            .absorb(nta.as_ref())?
            .absorb(enta.as_ref())?
            .commit()?
            .mask(tm)?
            .mask(ntm.as_ref())?
            .commit()?
            .squeeze(ents.as_mut())?
            .squeeze(&mac)?
            .commit()?
            .squeeze(External::new(&mut NBytes::new(&mut tag_wrap)))?;
        assert!(
            ctx.stream().is_empty(),
            "Output stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        let mut ta2 = Bytes::default();
        let mut nta2 = NBytes::<GenericArray<u8, U64>>::default();
        let mut tm2 = Bytes::<Vec<u8>>::default();
        let ntm2 = NBytes::<GenericArray<u8, U64>>::default();
        let mut ents2 = External::new(NBytes::<GenericArray<u8, U64>>::default());

        let mut ctx = unwrap::Context::<_, F>::new(&buf[..]);
        ctx.commit()?
            .absorb(ta2.as_mut())?
            .absorb(nta2.as_mut())?
            .absorb(enta.as_ref())?
            .commit()?
            .mask(tm2.as_mut())?
            .mask(ntm2)?
            .commit()?
            .squeeze(ents2.as_mut())?
            .squeeze(&mac)?
            .commit()?
            .squeeze(External::new(&mut NBytes::new(&mut tag_unwrap)))?;
        assert!(
            ctx.stream().is_empty(),
            "Input stream has not been exhausted. Remaining: {}",
            ctx.stream().len()
        );

        assert_eq!(ta, ta2, "Error comparing Bytes");
        assert_eq!(nta, nta2, "Error comparing NBytes");
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

fn absorb_ed25519<F: PRP + Default>() -> Result<()> {
    let secret = ed25519::SecretKey::from_bytes([7; ed25519::SECRET_KEY_LENGTH]);

    let tag_wrap = Bytes::new(vec![3u8; 17]);
    let mut tag_unwrap = Bytes::default();
    let mut hash_wrap = External::new(NBytes::new([0; 64]));
    let mut hash_unwrap = External::new(NBytes::new([0; 64]));

    let mut ctx = sizeof::Context::new();
    ctx.absorb(tag_wrap.as_ref())?
        .commit()?
        .squeeze(hash_wrap.as_ref())?
        .ed25519(&secret, hash_wrap.as_ref())?;
    let buf_size = ctx.finalize();

    let mut buf = vec![0u8; buf_size];

    let mut ctx = wrap::Context::<_, F>::new(&mut buf[..]);
    ctx.absorb(tag_wrap.as_ref())?
        .commit()?
        .squeeze(hash_wrap.as_mut())?
        .ed25519(&secret, hash_wrap.as_ref())?;
    assert!(
        ctx.stream().is_empty(),
        "Output stream has not been exhausted. Remaining: {}",
        ctx.stream().len()
    );

    let mut ctx = unwrap::Context::<_, F>::new(&buf[..]);
    ctx.absorb(tag_unwrap.as_mut())?
        .commit()?
        .squeeze(hash_unwrap.as_mut())?
        .ed25519(&secret.public_key(), hash_unwrap.as_ref())?;
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

fn x25519_transport<F: PRP + Default>() -> Result<()> {
    let mut prng = SpongosRng::<F>::new("seed for tests");
    let remote_secret_key = x25519::SecretKey::generate_with(&mut prng);

    let key_wrap = NBytes::<[u8; 32]>::new(prng.gen());
    let mut key_unwrap = NBytes::<[u8; 32]>::default();

    let mut ctx = sizeof::Context::new();
    ctx.x25519(&remote_secret_key.public_key(), key_wrap.as_ref())?;
    let buf_size = ctx.finalize();

    let mut buf = vec![0u8; buf_size];

    let mut ctx = wrap::Context::<_, F>::new(&mut buf[..]);
    ctx.x25519(&remote_secret_key.public_key(), key_wrap.as_ref())?;
    assert!(
        ctx.stream().is_empty(),
        "Output stream has not been exhausted. Remaining: {}",
        ctx.stream().len()
    );

    let mut ctx = unwrap::Context::<_, F>::new(&buf[..]);
    ctx.x25519(&remote_secret_key, key_unwrap.as_mut())?;
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
    assert!(x25519_transport::<KeccakF1600>().is_ok());
}
