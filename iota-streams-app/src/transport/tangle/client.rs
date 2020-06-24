use chrono::Utc;
use anyhow::{
    anyhow,
    bail,
    ensure,
    Result,
};
use std::{
    cmp::Ordering,
    convert::{TryInto, TryFrom},
    str::FromStr,
    string::ToString,
};
use smol::block_on;

use iota_constants::HASH_TRINARY_SIZE as HASH_LENGTH;
use iota_conversion::Trinary;
use iota::{
    client as iota_client,
    crypto as iota_crypto,
    bundle as iota_bundle,
    ternary as iota_ternary,
};

use iota_streams_core::tbits::{
    word::{
        BasicTbitWord,
        StringTbitWord,
    },
    TbitSlice,
    TbitSliceMut,
    Tbits,
    trinary::{TritWord, Trint1, Trit},
};

use crate::transport::{
    tangle::*,
    *,
};

/*
fn make_empty_tx() -> iota_bundle::Transaction {
    //8019
    let mut tx = iota_bundle::Transaction::default();
    //essense
    //243
    tx.address = "9".repeat(243 / 3);
    //81
    tx.value = 0;
    //81
    tx.obsolete_tag = "9".repeat(81 / 3);
    //27
    tx.timestamp = 0;
    //27
    tx.current_index = 0;
    //27
    tx.last_index = 0;
    //243
    tx.bundle = "9".repeat(243 / 3);

    //attachment
    //243
    tx.trunk_transaction = "9".repeat(243 / 3);
    //243
    tx.branch_transaction = "9".repeat(243 / 3);
    //
    tx.attachment_timestamp = 0;
    tx.attachment_timestamp_lower_bound = 0;
    tx.attachment_timestamp_upper_bound = 0;
    //81
    tx.nonce = "9".repeat(81 / 3);
    //81
    tx.tag = "9".repeat(81 / 3);

    //consensus
    //243
    tx.hash = "9".repeat(243 / 3);

    //data
    //6561
    tx.signature_fragments = "9".repeat(6561 / 3);

    tx.persistence = false;

    tx
}

fn make_tx<TW>(address: &Tbits<TW>, tag: &Tbits<TW>, msg: &Tbits<TW>, timestamp: i64) -> iota_bundle::Transaction
where
    TW: StringTbitWord,
{
    debug_assert_eq!(243, address.size());
    debug_assert_eq!(81, tag.size());
    debug_assert_eq!(6561, msg.size());

    let mut tx = make_empty_tx();
    tx.address = address.to_string();
    tx.tag = tag.to_string();
    tx.signature_fragments = msg.to_string();
    tx.timestamp = timestamp;
    tx
}

fn pad_trits<TW>(n: usize, s: TbitSlice<TW>) -> Tbits<TW>
where
    TW: BasicTbitWord,
{
    if n > s.size() {
        let mut t = Tbits::<TW>::zero(n);
        s.copy_min(&t.slice_mut());
        t
    } else {
        Tbits::<TW>::from_slice(s)
    }
}

fn make_txs<TW>(address: &Tbits<TW>, tag: &Tbits<TW>, msg: &Tbits<TW>, timestamp: i64) -> Vec<iota_bundle::Transaction>
where
    TW: StringTbitWord,
{
    debug_assert_eq!(243, address.size());
    debug_assert_eq!(81, tag.size());
    let msg_part_size = 6561;

    let mut txs = Vec::new();
    let mut m = msg.slice();
    while !m.is_empty() {
        txs.push(make_tx(
            address,
            tag,
            &pad_trits(msg_part_size, m.take_min(msg_part_size)),
            timestamp,
        ));
        m = m.drop_min(msg_part_size);
    }
    txs
}

/// Convert bundle to a list of tryte string for each transaction in the bundle.
/// The list is suitable for client's `send_trytes`.
///
/// The input bundle is expected to be valid.
/// This function may fail, in which case it returns an empty vector.
///
/// This functions is missing from iota-lib-rs for some reason.
pub fn bundle_to_trytes(bundle: &iota_bundle::Bundle) -> Vec<iota_conversion::Trytes> {
    let mut trytes = Vec::new();
    for tx in bundle.iter() {
        // This `try_into` conversion makes no sense. Why a transaction can't be converted to trytes?!
        if let Ok(t) = TryInto::<iota_conversion::Trytes>::try_into(tx) {
            trytes.push(t.clone());
        } else {
            return Vec::new();
        }
    }
    trytes
}

/// This functions is missing from iota-lib-rs for some reason.
fn calc_bundle_hash(bundle: &iota_bundle::Bundle) -> Result<String> {
    use iota_crypto::{
        Kerl,
        Sponge,
    };
    let mut kerl = Kerl::default();
    kerl.reset();
    for tx in bundle.iter() {
        let value_trits = tx.value.trits_with_length(81);
        let timestamp_trits = tx.timestamp.trits_with_length(27);
        let current_index_trits = (tx.current_index as i64).trits_with_length(27);
        let last_index_trits = (tx.last_index as i64).trits_with_length(27);
        let bundle_essence = tx.address.clone()
            + &value_trits.trytes()?
            + &tx.obsolete_tag
            + &timestamp_trits.trytes()?
            + &current_index_trits.trytes()?
            + &last_index_trits.trytes()?;
        kerl.absorb(&bundle_essence.trits())?;
    }
    let mut hash = [0; HASH_LENGTH];
    kerl.squeeze(&mut hash)?;
    hash.trytes()
}

/// This functions is missing from iota-lib-rs for some reason.
fn check_bundle_hash(bundle: &iota_bundle::Bundle) -> Result<()> {
    anyhow::ensure!(!bundle.is_empty());
    let hash = calc_bundle_hash(bundle)?;
    let mut current_index = 0usize;
    let last_index = bundle.len() - 1;
    for tx in bundle.iter() {
        anyhow::ensure!(tx.current_index == current_index);
        anyhow::ensure!(tx.last_index == last_index);
        anyhow::ensure!(tx.bundle == hash);
        current_index += 1;
    }
    Ok(())
}

/// Reconstruct valid bundles from trytes (returned by client's `get_trytes` method)
/// taking into account `addtess`, `tag` and `bundle` fields.
pub fn bundles_from_trytes(trytes: &Vec<iota_conversion::Trytes>) -> Vec<iota_bundle::Bundle> {
    let mut txs = trytes
        .into_iter()
        .filter_map(|t| t.parse().ok())
        .collect::<Vec<iota_bundle::Transaction>>();

    txs.sort_by(|x, y| {
        x.address
            .cmp(&y.address)
            .then(x.tag.cmp(&y.tag))
            // different messages may have the same bundle hash!
            .then(x.bundle.cmp(&y.bundle))
            // reverse order of txs will be extracted from back with `pop`
            .then(x.current_index.cmp(&y.current_index).reverse())
    });

    let mut bundles = Vec::new();

    if let Some(tx) = txs.pop() {
        let mut bundle = vec![tx];
        loop {
            if let Some(tx) = txs.pop() {
                if bundle[0].address == tx.address && bundle[0].tag == tx.tag && bundle[0].bundle == tx.bundle {
                    bundle.push(tx);
                } else {
                    bundles.push(bundle);
                    bundle = vec![tx];
                }
            } else {
                bundles.push(bundle);
                break;
            }
        }
    }

    bundles
        .into_iter()
        .filter_map(|txs| {
            let bundle = iota_bundle::Bundle::new(txs);
            if check_bundle_hash(&bundle).is_ok() {
                Some(bundle)
            } else {
                None
            }
        })
        .collect()
}

/// As Streams Message are packed into a bundle, and different bundles can have the same hash
/// (as bundle hash is calcualted over some essense fields including `address`, `timestamp`
/// and not including `tag`, so different Messages may end up in bundles with the same hash.
/// This leads that it may not be possible to STREAMS Messages from bundle hash only.
/// So this function also takes into account `address` and `tag` fields.
/// As STREAMS Messages can have the same message id (ie. `tag`) it is advised that STREAMS Message
/// bundles have distinct nonces and/or timestamps.
pub fn msg_to_bundle<TW, F>(msg: &TbinaryMessage<TW, F, TangleAddress<TW>>, timestamp: i64) -> iota_bundle::Bundle
where
    TW: StringTbitWord,
{
    let mut bundle = iota_bundle::Bundle::new(make_txs(
        msg.link().appinst.tbits(),
        msg.link().msgid.tbits(),
        &msg.body,
        timestamp,
    ));
    //bundle.add_trytes(&msg_chunks(msg));
    bundle.reset_indexes();
    let r = bundle.finalize();
    assert!(r.is_ok());
    bundle
}

/// Reconstruct STREAMS Message from bundle. The input bundle is not checked (for validity of
/// the hash, consistency of indices, etc.). Checked bundles are returned by `bundles_from_trytes`.
pub fn msg_from_bundle<TW, F>(bundle: &iota_bundle::Bundle) -> TbinaryMessage<TW, F, TangleAddress<TW>>
where
    TW: StringTbitWord,
{
    let tx = &bundle[0];
    let appinst = AppInst {
        id: NTrytes(Tbits::<TW>::from_str(&tx.address).unwrap()),
    };
    let msgid = MsgId {
        id: NTrytes(Tbits::<TW>::from_str(&tx.tag).unwrap()),
    };
    let mut body = Tbits::<TW>::zero(0);
    for tx in bundle.iter() {
        body += &Tbits::<TW>::from_str(&tx.signature_fragments).unwrap();
    }
    TbinaryMessage::new(TangleAddress::<TW> { appinst, msgid }, body)
}

#[cfg(test)]
fn bundle_from_to_trytes<TW, F>()
where
    TW: StringTbitWord,
{
    let appinst = AppInst {
        id: NTrytes(Tbits::<TW>::cycle_str(APPINST_SIZE, "A")),
    };
    // A,M,[D,E]
    let m1 = {
        let msgid = MsgId {
            id: NTrytes(Tbits::<TW>::cycle_str(MSGID_SIZE, "M")),
        };
        let body = &Tbits::<TW>::cycle_str(6561, "D") + &Tbits::<TW>::cycle_str(6561, "E");
        TbinaryMessage::<TW, F, TangleAddress<TW>>::new(TangleAddress::<TW>::new(appinst.clone(), msgid), body)
    };
    // A,N,[F,G]
    let m2 = {
        let msgid = MsgId {
            id: NTrytes(Tbits::<TW>::cycle_str(MSGID_SIZE, "N")),
        };
        let body = &Tbits::<TW>::cycle_str(6561, "F") + &Tbits::<TW>::cycle_str(6561, "G");
        TbinaryMessage::<TW, F, TangleAddress<TW>>::new(TangleAddress::<TW>::new(appinst.clone(), msgid), body)
    };

    let bundle1 = msg_to_bundle(&m1, 0);
    assert_eq!(2, bundle1.len());
    let tr1 = bundle_to_trytes(&bundle1);
    let tx1_0 = &tr1[0];
    let tx1_1 = &tr1[1];

    let bundle2 = msg_to_bundle(&m2, 0);
    assert_eq!(2, bundle2.len());
    let tr2 = bundle_to_trytes(&bundle2);
    let tx2_0 = &tr2[0];
    let tx2_1 = &tr2[1];

    if false {
        let trytes = vec![tx1_0.clone(), tx2_0.clone()];
        let bundles = bundles_from_trytes(&trytes);
        assert_eq!(bundles.len(), 0);
    }

    {
        let trytes = vec![tx2_1.clone(), tx1_0.clone(), tx2_0.clone()];
        let bundles = bundles_from_trytes(&trytes);
        assert_eq!(bundles.len(), 1);
        let m = msg_from_bundle::<TW, F>(&bundles[0]);
        assert_eq!(m.link(), m2.link());
        assert_eq!(m.body, m2.body);
    }

    {
        let trytes = vec![tx1_1.clone(), tx2_1.clone(), tx1_0.clone(), tx2_0.clone()];
        let bundles = bundles_from_trytes(&trytes);
        assert_eq!(bundles.len(), 2);
        let n1 = msg_from_bundle::<TW, F>(&bundles[0]);
        let n2 = msg_from_bundle::<TW, F>(&bundles[1]);
        assert!(
            (n1.link() == m1.link() && n1.body == m1.body && n2.link() == m2.link() && n2.body == m2.body)
                || (n1.link() == m2.link() && n1.body == m2.body && n2.link() == m1.link() && n2.body == m1.body)
        );
    }
}

#[cfg(test)]
#[test]
fn test_bundle_from_to_trytes() {
    use iota_streams_core::{
        sponge::prp::troika::Troika,
        tbits::trinary::Trit,
    };
    bundle_from_to_trytes::<Trit, Troika>();
}

/// Stripped version of `iota_client::options::SendTrytesOptions<'a>` due to lifetime parameter.
#[derive(Clone, Copy)]
pub struct SendTrytesOptions {
    pub depth: usize,
    pub min_weight_magnitude: usize,
    pub local_pow: bool,
    pub threads: usize,
}

impl Default for SendTrytesOptions {
    fn default() -> Self {
        Self {
            depth: 3,
            min_weight_magnitude: 14,
            local_pow: true,
            threads: num_cpus::get(),
        }
    }
}

impl<'a, TW, F> Transport<TW, F, TangleAddress<TW>> for iota_client::Client<'a>
where
    TW: StringTbitWord,
{
    type SendOptions = SendTrytesOptions;

    /// Send a Streams message over the Tangle with the current timestamp and default SendTrytesOptions.
    fn send_message_with_options(
        &mut self,
        msg: &TbinaryMessage<TW, F, TangleAddress<TW>>,
        opt: Self::SendOptions,
    ) -> Result<()> {
        iota_client::SendTrytesBuilder {
            client: self,
            depth: opt.depth,
            min_weight_magnitude: opt.min_weight_magnitude,
            local_pow: opt.local_pow,
            threads: opt.threads,
            reference: None,
        };
        let timestamp = Utc::now().timestamp();
        let bundle = msg_to_bundle(msg, timestamp);
        let trytes = bundle_to_trytes(&bundle);
        // Ignore PoWed transactions.
        let _txs = self.send_trytes(&trytes, opt)?;
        Ok(())
    }

    type RecvOptions = ();

    /// Receive a message.
    fn recv_messages_with_options(
        &mut self,
        link: &TangleAddress<TW>,
        _opt: Self::RecvOptions,
    ) -> Result<Vec<TbinaryMessage<TW, F, TangleAddress<TW>>>> {
        let find_opt = iota_client::options::FindTransactionsOptions {
            bundles: Vec::new(),
            addresses: vec![link.appinst.to_string()],
            tags: vec![link.msgid.to_string()],
            approvees: Vec::new(),
        };

        print!("  finding tx ... ");
        let find_resp = self.find_transactions(find_opt)?;
        println!("  done");
        if let Some(e) = find_resp.error() {
            bail!("Find transactions failed with error: {}.", e)
        } else if let Some(hashes) = find_resp.take_hashes() {
            ensure!(!hashes.is_empty(), "Empty transaction hashes found.");
            print!("  getting trytes ... ");
            let get_resp = self.get_trytes(&hashes)?;
            println!("  done");
            if let Some(e) = get_resp.error() {
                bail!("Get trytes failed with error: {}.", e)
            } else if let Some(trytes) = get_resp.take_trytes() {
                return Ok(bundles_from_trytes(&trytes)
                    .into_iter()
                    .map(|bundle| msg_from_bundle(&bundle))
                    .collect());
            } else {
                bail!("Get trytes contains no trytes.")
            }
        } else {
            bail!("No transaction hashes found.")
        }
    }
}
 */

use {
    iota_bundle::{
        Address,
        Hash,
        IncomingBundleBuilder,
        Index,
        Nonce,
        OutgoingBundleBuilder,
        Payload,
        Tag,
        Timestamp,
        Transaction,
        TransactionBuilder,
        TransactionBuilders,
        TransactionError,
        TransactionField,
        Transactions,
        Value,
    },
};

fn pad_trits<TW>(n: usize, s: TbitSlice<TW>) -> Tbits<TW>
where
    TW: BasicTbitWord,
{
    if n > s.size() {
        let mut t = Tbits::<TW>::zero(n);
        s.copy_min(&t.slice_mut());
        t
    } else {
        Tbits::<TW>::from_slice(s)
    }
}

fn tbitslice_to_tritbuf<TW>(slice: TbitSlice<TW>) -> iota_ternary::TritBuf<iota_ternary::T1B1Buf> where
    TW: TritWord,
{
    let mut tbits = vec![TW::ZERO_TBIT; slice.size()];
    slice.get_tbits(&mut tbits[..]);
    let btrits = tbits
        .iter()
        .map(|&tbit| iota_ternary::Btrit::try_from(tbit.0 as i8 - 1))
        .filter_map(Result::ok)
        .collect::<Vec<iota_ternary::Btrit>>();
    iota_ternary::TritBuf::from_trits(&btrits[..])
}

fn tbits_to_tritbuf<TW>(tbits: &Tbits<TW>) -> iota_ternary::TritBuf<iota_ternary::T1B1Buf> where
    TW: TritWord,
{
    tbitslice_to_tritbuf(tbits.slice())
}

fn tbitslice_from_tritbuf<TW>(buf: &iota_ternary::TritBuf<iota_ternary::T1B1Buf>, slice: TbitSliceMut<TW>) where
    TW: TritWord,
{
    assert_eq!(buf.len(), slice.size());
    let trits = buf
        .trits()
        .map(|trit| Trit((i8::from(trit) + 1) as u8))
        .collect::<Vec<Trit>>();
    slice.put_tbits(&trits[..]);
}

fn tbits_from_tritbuf<TW>(buf: &iota_ternary::TritBuf<iota_ternary::T1B1Buf>) -> Tbits<TW> where
    TW: TritWord,
{
    let mut tbits = Tbits::zero(buf.len());
    tbitslice_from_tritbuf(buf, tbits.slice_mut());
    tbits
}

fn cmp_tritbuf(a: &iota_ternary::TritBuf<iota_ternary::T1B1Buf>, b: &iota_ternary::TritBuf<iota_ternary::T1B1Buf>) -> Ordering {
    a.trits().cmp(b.trits())
}

fn cmp_trits(a: &iota_ternary::Trits<iota_ternary::T1B1>, b: &iota_ternary::Trits<iota_ternary::T1B1>) -> Ordering {
    a.trits().cmp(b.trits())
}

fn make_tx(tx_address: Address, tx_tag: Tag, tx_timestamp: Timestamp, tx_payload: Payload) -> iota_bundle::TransactionBuilder {
    use iota_bundle::*;

    let mut tx_builder = TransactionBuilder::new();

    tx_builder
        .with_payload(tx_payload)
        .with_address(tx_address)
        .with_value(Value::from_inner_unchecked(0))
        .with_obsolete_tag(Tag::zeros())
        .with_timestamp(tx_timestamp)
        .with_index(Index::from_inner_unchecked(0))
        .with_last_index(Index::from_inner_unchecked(0))
        .with_tag(tx_tag)
        .with_attachment_ts(Timestamp::from_inner_unchecked(0))
        .with_bundle(Hash::zeros())
        .with_trunk(Hash::zeros())
        .with_branch(Hash::zeros())
        .with_attachment_lbts(Timestamp::from_inner_unchecked(0))
        .with_attachment_ubts(Timestamp::from_inner_unchecked(0))
        .with_nonce(Nonce::zeros())
}

fn make_bundle<TW>(address: &Tbits<TW>, tag: &Tbits<TW>, body: &Tbits<TW>, timestamp: u64, trunk: iota_bundle::Hash, branch: iota_bundle::Hash) -> Result<iota_bundle::Bundle>
    where
    TW: BasicTbitWord + TritWord,
{
    let tx_address = Address::try_from_inner(tbits_to_tritbuf(address))
        .map_err(|e| anyhow!("Bad tx address: {:?}.", e))?;
    let tx_tag = Tag::try_from_inner(tbits_to_tritbuf(tag))
        .map_err(|e| anyhow!("Bad tx tag: {:?}.", e))?;
    let tx_timestamp = Timestamp::try_from_inner(timestamp)
        .map_err(|e| anyhow!("Bad tx timestamp: {:?}.", e))?;

    let mut bundle_builder = OutgoingBundleBuilder::new();
    let mut body_slice = body.slice();
    while body_slice.size() >= iota_bundle::PAYLOAD_TRIT_LEN {
        let payload_chunk = body_slice.take(iota_bundle::PAYLOAD_TRIT_LEN);
        let tx_payload = Payload::try_from_inner(tbitslice_to_tritbuf(payload_chunk))
            .map_err(|e| anyhow!("Failed to create payload chunk: {:?}.", e))?;
        bundle_builder.push(make_tx(
            tx_address.clone(),
            tx_tag.clone(),
            tx_timestamp.clone(),
            tx_payload));
        body_slice = body_slice.drop(iota_bundle::PAYLOAD_TRIT_LEN);
    }
    if !body_slice.is_empty() {
        let payload_last_chunk = pad_trits(iota_bundle::PAYLOAD_TRIT_LEN, body_slice);
        let tx_payload = Payload::try_from_inner(tbits_to_tritbuf(&payload_last_chunk))
            .map_err(|e| anyhow!("Failed to create payload chunk: {:?}.", e))?;
        bundle_builder.push(make_tx(
            tx_address.clone(),
            tx_tag.clone(),
            tx_timestamp.clone(),
            tx_payload));
    }

    bundle_builder
        .seal()
        .map_err(|e| anyhow!("Failed to seal bundle: {:?}.", e))?
        //TODO: `attach_remote` is not implemented in iota-bundle-preview atm.
        .attach_remote(trunk, branch)
        .map_err(|e| anyhow!("Failed to attach bundle: {:?}.", e))?
        .build()
        .map_err(|e| anyhow!("Failed to build bundle: {:?}.", e))
}

/// Reconstruct valid bundles from trytes (returned by client's `get_trytes` method)
/// taking into account `addtess`, `tag` and `bundle` fields.
pub fn bundles_from_trytes(mut txs: Vec<iota_bundle::Transaction>) -> Vec<iota_bundle::Bundle> {
    txs.sort_by(|x, y| {
        //TODO: impl Ord for Address, Tag, Hash
        cmp_tritbuf(x.address().to_inner(), y.address().to_inner())
            .then(cmp_tritbuf(x.tag().to_inner(), y.tag().to_inner()))
            // different messages may have the same bundle hash!
            .then(cmp_trits(x.bundle().to_inner(), y.bundle().to_inner()))
            // reverse order of txs will be extracted from back with `pop`
            .then(x.index().to_inner().cmp(y.index().to_inner()).reverse())
    });

    let mut bundles = Vec::new();

    if let Some(tx) = txs.pop() {
        let mut bundle = vec![tx];
        loop {
            if let Some(tx) = txs.pop() {
                if bundle[0].address() == tx.address() && bundle[0].tag() == tx.tag() && bundle[0].bundle() == tx.bundle() {
                    bundle.push(tx);
                } else {
                    bundles.push(bundle);
                    bundle = vec![tx];
                }
            } else {
                bundles.push(bundle);
                break;
            }
        }
    }

    bundles
        .into_iter()
        .filter_map(|txs| {
            let mut bundle_builder = iota_bundle::IncomingBundleBuilder::new();
            txs.into_iter().map(|tx| bundle_builder.push(tx));
            bundle_builder.validate().map(|b| b.build()).ok()
        })
        .collect()
    /*
    bundles
        .into_iter()
        .filter_map(|txs| {
            let bundle = iota_bundle::Bundle::new(txs);
            if check_bundle_hash(&bundle).is_ok() {
                Some(bundle)
            } else {
                None
            }
        })
        .collect()
     */
}

/// Reconstruct Streams Message from bundle. The input bundle is not checked (for validity of
/// the hash, consistency of indices, etc.). Checked bundles are returned by `bundles_from_trytes`.
pub fn msg_from_bundle<TW, F>(bundle: &iota_bundle::Bundle) -> TbinaryMessage<TW, F, TangleAddress<TW>>
where
    TW: StringTbitWord + TritWord,
{
    let tx = bundle.head();
    let appinst = AppInst {
        id: NTrytes(tbits_from_tritbuf::<TW>(tx.address().to_inner())),
    };
    let msgid = MsgId {
        id: NTrytes(tbits_from_tritbuf::<TW>(tx.tag().to_inner())),
    };
    let mut body = Tbits::<TW>::zero(0);
    for tx in bundle.into_iter() {
        body += &tbits_from_tritbuf::<TW>(tx.payload().to_inner());
    }
    TbinaryMessage::new(TangleAddress::<TW> { appinst, msgid }, body)
}

/// As Streams Message are packed into a bundle, and different bundles can have the same hash
/// (as bundle hash is calcualted over some essense fields including `address`, `timestamp`
/// and not including `tag`, so different Messages may end up in bundles with the same hash.
/// This leads that it may not be possible to STREAMS Messages from bundle hash only.
/// So this function also takes into account `address` and `tag` fields.
/// As STREAMS Messages can have the same message id (ie. `tag`) it is advised that STREAMS Message
/// bundles have distinct nonces and/or timestamps.
pub fn msg_to_bundle<TW, F>(msg: &TbinaryMessage<TW, F, TangleAddress<TW>>, timestamp: u64, trunk: iota_bundle::Hash, branch: iota_bundle::Hash) -> Result<iota_bundle::Bundle>
where
    TW: BasicTbitWord + TritWord,
{
    make_bundle(
        msg.link.appinst.tbits(),
        msg.link.msgid.tbits(),
        &msg.body,
        timestamp,
        trunk,
        branch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvt() {
        let tbits = Tbits::<Trit>::from_str("DEADBEEF").unwrap();
        let buf = tbits_to_tritbuf(&tbits);
        let tbits2 = tbits_from_tritbuf::<Trit>(&buf);
        assert_eq!(tbits, tbits2);
    }

    #[test]
    fn cmp() {
        let x = iota_ternary::TritBuf::<iota_ternary::T1B1Buf>::new();
        let x0 = iota_ternary::TritBuf::<iota_ternary::T1B1Buf>::zeros(1);
        let x00 = iota_ternary::TritBuf::<iota_ternary::T1B1Buf>::zeros(2);
        let x1 = iota_ternary::TritBuf::<iota_ternary::T1B1Buf>::filled(1, iota_ternary::Btrit::try_from(1i8).unwrap());
        let x11 = iota_ternary::TritBuf::<iota_ternary::T1B1Buf>::filled(2, iota_ternary::Btrit::try_from(1i8).unwrap());
        assert_eq!(Ordering::Less, cmp_tritbuf(&x, &x0));
        assert_eq!(Ordering::Greater, cmp_tritbuf(&x1, &x0));
        assert_eq!(Ordering::Greater, cmp_tritbuf(&x1, &x0));
    }

    fn bundle_from_to_trytes<TW, F>()
        where
        TW: StringTbitWord + TritWord,
    {
        let trunk = iota_bundle::Hash::zeros();
        let branch = iota_bundle::Hash::zeros();

        let appinst = AppInst {
            id: NTrytes(Tbits::<TW>::cycle_str(APPINST_SIZE, "A")),
        };
        // A,M,[D,E]
        let m1 = {
            let msgid = MsgId {
                id: NTrytes(Tbits::<TW>::cycle_str(MSGID_SIZE, "M")),
            };
            let body = &Tbits::<TW>::cycle_str(6561, "D") + &Tbits::<TW>::cycle_str(6561, "E");
            TbinaryMessage::<TW, F, TangleAddress<TW>>::new(TangleAddress::<TW>::new(appinst.clone(), msgid), body)
        };
        // A,N,[F,G]
        let m2 = {
            let msgid = MsgId {
                id: NTrytes(Tbits::<TW>::cycle_str(MSGID_SIZE, "N")),
            };
            let body = &Tbits::<TW>::cycle_str(6561, "F") + &Tbits::<TW>::cycle_str(6561, "G");
            TbinaryMessage::<TW, F, TangleAddress<TW>>::new(TangleAddress::<TW>::new(appinst.clone(), msgid), body)
        };

        let bundle1 = msg_to_bundle(&m1, 0, trunk.clone(), branch.clone()).unwrap();
        assert_eq!(2, bundle1.len());
        let tx1_0 = bundle1.get(0).unwrap();
        let tx1_1 = bundle1.get(1).unwrap();

        let bundle2 = msg_to_bundle(&m2, 0, trunk.clone(), branch.clone()).unwrap();
        assert_eq!(2, bundle2.len());
        let tx2_0 = bundle2.get(0).unwrap();
        let tx2_1 = bundle1.get(1).unwrap();

        if false {
            let trytes = vec![tx1_0.clone(), tx2_0.clone()];
            let bundles = bundles_from_trytes(trytes);
            assert_eq!(0, bundles.len());
        }

        {
            let trytes = vec![tx2_1.clone(), tx1_0.clone(), tx2_0.clone()];
            let bundles = bundles_from_trytes(trytes);
            assert_eq!(1, bundles.len());
            let m = msg_from_bundle::<TW, F>(&bundles[0]);
            assert_eq!(m, m2);
        }

        {
            let trytes = vec![tx1_1.clone(), tx2_1.clone(), tx1_0.clone(), tx2_0.clone()];
            let bundles = bundles_from_trytes(trytes);
            assert_eq!(bundles.len(), 2);
            let n1 = msg_from_bundle::<TW, F>(&bundles[0]);
            let n2 = msg_from_bundle::<TW, F>(&bundles[1]);
            assert!(
                (n1 == m1 && n2 == m2) || (n1 == m2 && n1 == m1)
            );
        }
    }

    #[test]
    fn test_bundle_from_to_trytes() {
        use iota_streams_core::{
            sponge::prp::troika::Troika,
            tbits::trinary::Trit,
        };
        bundle_from_to_trytes::<Trit, Troika>();
    }
}

#[derive(Clone, Copy)]
pub struct SendTrytesOptions {
    pub depth: u8,
    pub min_weight_magnitude: u8,
}

async fn send_message<TW, F>(
    msg: &TbinaryMessage<TW, F, TangleAddress<TW>>,
    opt: SendTrytesOptions,
) -> Result<()> where
    TW: TritWord,
{
    let timestamp = Utc::now().timestamp() as u64;
    //TODO: Get trunk and branch hashes. Although, `send_trytes` should get these hashes.
    let trunk = Hash::zeros();
    let branch = Hash::zeros();
    let bundle = msg_to_bundle(msg, timestamp, trunk, branch)?;
    //TODO: Get transactions from bundle without copying.
    let txs = bundle.into_iter().collect::<Vec<iota_bundle::Transaction>>();
    // Ignore attached transactions.
    let _attached_txs = iota_client::Client::send_trytes()
        .min_weight_magnitude(opt.min_weight_magnitude)
        .depth(opt.depth)
        .trytes(txs)
        .send()
        .await?;
    Ok(())
}

async fn recv_messages<TW, F>(
    link: &TangleAddress<TW>,
) -> Result<Vec<TbinaryMessage<TW, F, TangleAddress<TW>>>> where
    TW: StringTbitWord + TritWord,
{
    let tx_address = Address::try_from_inner(tbits_to_tritbuf(link.appinst.tbits()))
        .map_err(|e| anyhow!("Bad tx address: {:?}.", e))?;
    let tx_tag = Tag::try_from_inner(tbits_to_tritbuf(link.msgid.tbits()))
        .map_err(|e| anyhow!("Bad tx tag: {:?}.", e))?;

    let find_resp = iota_client::Client::find_transactions()
        .addresses(&vec![tx_address])
        .tags(&vec![tx_tag])
        .send()
        .await?;
    ensure!(!find_resp.hashes.is_empty(), "Transaction hashes not found.");
    let get_resp = iota_client::Client::get_trytes(&find_resp.hashes[..])
        .await?;
    ensure!(!get_resp.trytes.is_empty(), "Transactions not found.");
    Ok(bundles_from_trytes(get_resp.trytes)
       .into_iter()
       .map(|b| msg_from_bundle(&b))
       .collect())
}

impl<TW, F> Transport<TW, F, TangleAddress<TW>> for iota_client::Client
where
    TW: StringTbitWord + TritWord,
{
    type SendOptions = SendTrytesOptions;

    /// Send a Streams message over the Tangle with the current timestamp and default SendTrytesOptions.
    fn send_message_with_options(
        &mut self,
        msg: &TbinaryMessage<TW, F, TangleAddress<TW>>,
        opt: Self::SendOptions,
    ) -> Result<()> {
        let result = send_message(msg, opt);
        block_on(result)
    }

    type RecvOptions = ();

    /// Receive a message.
    fn recv_messages_with_options(
        &mut self,
        link: &TangleAddress<TW>,
        _opt: Self::RecvOptions,
    ) -> Result<Vec<TbinaryMessage<TW, F, TangleAddress<TW>>>> {
        let result = recv_messages(link,);
        block_on(result)
    }
}
