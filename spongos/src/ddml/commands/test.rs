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
    F: PRP + Default,
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
    F: PRP + Default,
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
    F: PRP + Default,
{
    const NS: [usize; 10] = [0, 3, 255, 256, 257, 483, 486, 489, 1002, 2001];

    let mut tag_wrap = External::new(NBytes::<[u8; 32]>::default());
    let mut tag_unwrap = External::new(NBytes::<[u8; 32]>::default());

    let mut prng = SpongosRng::<F>::new("Spongos tests");

    for &n in NS.iter() {
        let ta = Bytes::<Vec<u8>>::new(prng.borrow_mut().sample_iter(Standard).take(n).collect());
        let nta: NBytes<GenericArray<u8, U64>> = prng.gen();
        let enta: NBytes<GenericArray<u8, U64>> = prng.gen();
        let tm = Bytes::<Vec<u8>>::new(prng.borrow_mut().sample_iter(Standard).take(n).collect());
        let ntm: NBytes<GenericArray<u8, U64>> = prng.gen();
        let mut ents = External::new(NBytes::<GenericArray<u8, U64>>::default());
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

fn x25519_transport<F: PRP + Default>() -> Result<()> {
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
    assert!(x25519_transport::<KeccakF1600>().is_ok());
}
