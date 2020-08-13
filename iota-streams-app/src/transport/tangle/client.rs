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
    transaction::{
        Vertex,
        bundled as iota_bundle
    },
    ternary as iota_ternary,
};

use crate::transport::{
    tangle::*,
    *,
};

use {
    iota_bundle::{
        Address,
        IncomingBundleBuilder,
        Index,
        Nonce,
        OutgoingBundleBuilder,
        Payload,
        Tag,
        Timestamp,
        BundledTransaction,
        BundledTransactionBuilder,
        BundledTransactionBuilders,
        BundledTransactionError,
        BundledTransactionField,
        BundledTransactions,
        Value,
    },
};

use bee_crypto::ternary::Hash;

const TRYTE_CHARS: &str = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn pad_trit_buf(n: usize, mut s: iota_ternary::TritBuf<iota_ternary::T1B1Buf>) -> iota_ternary::TritBuf<iota_ternary::T1B1Buf> {
    if n > s.len() {
        for _ in 0..n - s.len() {
            s.push(iota_ternary::trit::Trit::zero());
        }
        s
    } else {
        s
    }
}

fn tbitslice_to_tritbuf(mut slice: Vec<u8>) -> iota_ternary::TritBuf<iota_ternary::T1B1Buf> {
    let tbits = slice.as_mut_slice();
    let temp = bytes_to_trytes(tbits);
    temp
}

fn bytes_to_trytes(input: &[u8]) -> iota_ternary::TritBuf<iota_ternary::T1B1Buf>{
    let mut trytes = iota_ternary::TryteBuf::with_capacity(input.len() * 2);
    for byte in input {
        let first: i8 = match (byte % 27) as i8 {
            b @ 0..=13 => b,
            b @ 14..=26 => b - 27,
            _ => unreachable!(),
        };
        let second = match (byte / 27) as i8 {
            b @ 0..=13 => b,
            b @ 14..=26 => b - 27,
            _ => unreachable!(),
        };
        trytes.push(first.try_into().unwrap());
        trytes.push(second.try_into().unwrap());
    }
    trytes.as_trits().encode::<iota_ternary::T1B1Buf>()
}

fn trits_to_bytes(input: &iota_ternary::TritBuf<iota_ternary::T3B1Buf>) -> Vec<u8> {
    let trytes = input
        .chunks(3)
        .map(|trit| {
            char::from(iota_ternary::Tryte::from_trits([
                trit.get(0).unwrap(),
                trit.get(1).unwrap(),
                trit.get(2).unwrap(),
            ]))
        })
        .collect::<String>();

    let mut bytes = Vec::new();

    for i in 0..trytes.len()/2 {
        // get a trytes pair
        let char1 = trytes.get(i * 2.. i * 2 + 1).unwrap();
        let char2 = trytes.get(i * 2 + 1.. i*2 + 2).unwrap();

        let first_value = TRYTE_CHARS.find(char1).unwrap();
        let second_value = TRYTE_CHARS.find(char2).unwrap();

        let value = first_value + second_value * 27;
        bytes.push(value as u8);
    }

    bytes.to_vec()
}


fn tbits_to_tritbuf(tbits: &Vec<u8>) -> iota_ternary::TritBuf<iota_ternary::T1B1Buf> {
    tbitslice_to_tritbuf(tbits.to_vec())
}

fn tbitslice_from_tritbuf(buf: &iota_ternary::Trits<iota_ternary::T1B1>) -> Vec<u8>{
   trits_to_bytes(&buf.encode())
}

fn tbits_from_tritbuf(buf: &iota_ternary::Trits<iota_ternary::T1B1>) -> Vec<u8> {
    tbitslice_from_tritbuf(buf)
}

fn cmp_tritbuf(a: &iota_ternary::TritBuf<iota_ternary::T1B1Buf>, b: &iota_ternary::TritBuf<iota_ternary::T1B1Buf>) -> Ordering {
    a.iter().cmp(b.iter())
}

fn cmp_trits(a: &iota_ternary::Trits<iota_ternary::T1B1>, b: &iota_ternary::Trits<iota_ternary::T1B1>) -> Ordering {
    a.iter().cmp(b.iter())
}

fn make_tx(tx_address: Address, tx_tag: Tag, tx_timestamp: Timestamp, tx_payload: Payload) -> iota_bundle::BundledTransactionBuilder {
    use iota_bundle::*;

    let mut tx_builder = BundledTransactionBuilder::new();

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

fn make_bundle(address: &Vec<u8>, tag: &Vec<u8>, body: &Vec<u8>, timestamp: u64, trunk: Hash, branch: Hash) -> Result<iota_bundle::Bundle> {
    let tx_address = Address::try_from_inner(pad_trit_buf(iota_bundle::ADDRESS_TRIT_LEN, tbits_to_tritbuf(address)))
        .map_err(|e| anyhow!("Bad tx address: {:?}.", e))?;
    let tx_tag = Tag::try_from_inner(pad_trit_buf(iota_bundle::TAG_TRIT_LEN, tbits_to_tritbuf(tag)))
        .map_err(|e| anyhow!("Bad tx tag: {:?}.", e))?;
    let tx_timestamp = Timestamp::try_from_inner(timestamp)
        .map_err(|e| anyhow!("Bad tx timestamp: {:?}.", e))?;

    let mut bundle_builder = OutgoingBundleBuilder::new();
    let mut body_slice = body.clone();
    while body_slice.len() >= iota_bundle::PAYLOAD_TRIT_LEN {
        let (payload_chunk, new_body_slice) = body_slice.split_at_mut(iota_bundle::PAYLOAD_TRIT_LEN);
        let tx_payload = Payload::try_from_inner(tbitslice_to_tritbuf(payload_chunk.to_vec()))
            .map_err(|e| anyhow!("Failed to create payload chunk: {:?}.", e))?;
        bundle_builder.push(make_tx(
            tx_address.clone(),
            tx_tag.clone(),
            tx_timestamp.clone(),
            tx_payload));
        body_slice = new_body_slice.to_vec();
    }
    if !body_slice.is_empty() {
        let temp = pad_trit_buf(iota_bundle::PAYLOAD_TRIT_LEN, tbits_to_tritbuf(&body_slice));
        let tx_payload = Payload::try_from_inner(temp.clone())
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
pub fn bundles_from_trytes(mut txs: Vec<iota_bundle::BundledTransaction>) -> Vec<iota_bundle::Bundle> {
    txs.sort_by(|x, y| {
        //TODO: impl Ord for Address, Tag, Hash
        cmp_trits(x.address().to_inner(), y.address().to_inner())
            .then(cmp_trits(x.tag().to_inner(), y.tag().to_inner()))
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
            //TODO: This needs a proper incoming bundle building implementation, but it is not currently available
            let mut bundle_builder = iota_bundle::OutgoingBundleBuilder::new();
            let mut trunk = Hash::zeros();
            let mut branch = Hash::zeros();
            for tx in txs.into_iter() {
                let mut tx_builder = BundledTransactionBuilder::new();

                let tx_builder = tx_builder
                    .with_payload(tx.payload().clone())
                    .with_address(tx.address().clone())
                    .with_value(tx.value().clone())
                    .with_obsolete_tag(tx.obsolete_tag().clone())
                    .with_timestamp(tx.timestamp().clone())
                    .with_index(tx.index().clone())
                    .with_last_index(tx.last_index().clone())
                    .with_tag(tx.tag().clone())
                    .with_attachment_ts(tx.attachment_ts().clone())
                    .with_bundle(tx.bundle().clone())
                    .with_trunk(trunk.clone())
                    .with_branch(branch.clone())
                    .with_attachment_lbts(tx.attachment_lbts().clone())
                    .with_attachment_ubts(tx.attachment_ubts().clone())
                    .with_nonce(tx.nonce().clone());

                trunk = *tx.trunk();
                branch = *tx.branch();

                bundle_builder.push(tx_builder);
            };

            let bundle_builder = bundle_builder
                .seal()
                .map_err(|e| anyhow!("Failed to seal incoming bundle: {:?}.", e)).unwrap()
                .attach_remote(trunk, branch)
                .map_err(|e| anyhow!("Failed to attach bundle: {:?}.", e)).unwrap()
                .build()
                .map_err(|e| anyhow!("Failed to build incoming bundle: {:?}.", e)).unwrap();

            Some(bundle_builder)
        })
        .collect()
}

/// Reconstruct Streams Message from bundle. The input bundle is not checked (for validity of
/// the hash, consistency of indices, etc.). Checked bundles are returned by `bundles_from_trytes`.
pub fn msg_from_bundle<F>(bundle: &iota_bundle::Bundle, multi_branching: u8) -> TbinaryMessage<F, TangleAddress>{
    let tx = bundle.head();
    let appinst = AppInst {
        id: NBytes(tbits_from_tritbuf(tx.address().to_inner())),
    };

    let mut tbits = tbits_from_tritbuf(tx.tag().to_inner());
    tbits.truncate(MSGID_SIZE);
    let msgid = MsgId {
        id: NBytes(tbits),
    };
    let mut body = Vec::new();
    for tx in bundle.into_iter() {
        body.extend_from_slice(&tbits_from_tritbuf(tx.payload().to_inner()));
    }
    TbinaryMessage::new(TangleAddress { appinst, msgid }, body, multi_branching)
}

/// As Streams Message are packed into a bundle, and different bundles can have the same hash
/// (as bundle hash is calcualted over some essense fields including `address`, `timestamp`
/// and not including `tag`, so different Messages may end up in bundles with the same hash.
/// This leads that it may not be possible to STREAMS Messages from bundle hash only.
/// So this function also takes into account `address` and `tag` fields.
/// As STREAMS Messages can have the same message id (ie. `tag`) it is advised that STREAMS Message
/// bundles have distinct nonces and/or timestamps.
pub fn msg_to_bundle<F>(msg: &TbinaryMessage<F, TangleAddress>, timestamp: u64, trunk: Hash, branch: Hash) -> Result<iota_bundle::Bundle> {
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
        let tbits2 = tbits_from_tritbuf(&buf);
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
        let trunk = Hash::zeros();
        let branch = Hash::zeros();

        let appinst = AppInst {
            id: NTrytes(Tbits::<TW>::cycle_str(APPINST_SIZE, "A")),
        };
        // A,M,[D,E]
        let m1 = {
            let msgid = MsgId {
                id: NTrytes(Tbits::<TW>::cycle_str(MSGID_SIZE, "M")),
            };
            let body = &Tbits::<TW>::cycle_str(6561, "D") + &Tbits::<TW>::cycle_str(6561, "E");
            TbinaryMessage::<TW, F, TangleAddress<TW>>::new(TangleAddress::<TW>::new(appinst.clone(), msgid), body, 0)
        };
        // A,N,[F,G]
        let m2 = {
            let msgid = MsgId {
                id: NTrytes(Tbits::<TW>::cycle_str(MSGID_SIZE, "N")),
            };
            let body = &Tbits::<TW>::cycle_str(6561, "F") + &Tbits::<TW>::cycle_str(6561, "G");
            TbinaryMessage::<TW, F, TangleAddress<TW>>::new(TangleAddress::<TW>::new(appinst.clone(), msgid), body, 0)
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
            let m = msg_from_bundle(&bundles[0], 0);
            assert_eq!(m, m2);
        }

        {
            let trytes = vec![tx1_1.clone(), tx2_1.clone(), tx1_0.clone(), tx2_0.clone()];
            let bundles = bundles_from_trytes(trytes);
            assert_eq!(bundles.len(), 2);
            let n1 = msg_from_bundle(&bundles[0], 0);
            let n2 = msg_from_bundle(&bundles[1], 0);
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


async fn get_bundles(client: &iota_client::Client, tx_address: Address, tx_tag: Tag) -> Result<Vec<BundledTransaction>>{
    let find_resp = client.find_transactions()
        .addresses(&vec![tx_address][..])
        .tags(&vec![tx_tag][..])
        .send()
        .await?;
    ensure!(!find_resp.hashes.is_empty(), "Transaction hashes not found.");
    let get_resp = client.get_trytes(&find_resp.hashes[..])
    .await?;
    ensure!(!get_resp.trytes.is_empty(), "Transactions not found.");
    Ok(get_resp.trytes)
}


async fn send_trytes(client: &iota_client::Client, opt: SendTrytesOptions, txs: Vec<iota_bundle::BundledTransaction>) -> Result<Vec<BundledTransaction>> {
    let attached_txs = client.send_trytes()
        .min_weight_magnitude(opt.min_weight_magnitude)
        .depth(opt.depth)
        .trytes(txs)
        .send()
        .await?;
    Ok(attached_txs)
}




impl<F> Transport<F, TangleAddress> for iota_client::Client {
    type SendOptions = SendTrytesOptions;

    /// Send a Streams message over the Tangle with the current timestamp and default SendTrytesOptions.
    fn send_message_with_options(
        &mut self,
        msg: &TbinaryMessage<F, TangleAddress>,
        opt: Self::SendOptions,
    ) -> Result<()> {
        let timestamp = Utc::now().timestamp() as u64;
        //println!("Sending...");
        //TODO: Get trunk and branch hashes. Although, `send_trytes` should get these hashes.
        let trunk = Hash::zeros();
        let branch = Hash::zeros();
        let bundle = msg_to_bundle(msg, timestamp, trunk, branch)?;
        //TODO: Get transactions from bundle without copying.
        let txs = bundle.into_iter().collect::<Vec<iota_bundle::BundledTransaction>>();
        // Ignore attached transactions.
        block_on(send_trytes(self, opt, txs));
        Ok(())
    }

    type RecvOptions = ();

    /// Receive a message.
    fn recv_messages_with_options(
        &mut self,
        link: &TangleAddress,
        multi_branching: u8,
        _opt: Self::RecvOptions,
    ) -> Result<Vec<TbinaryMessage<F, TangleAddress>>> {
        //println!("Receiving...");
        let tx_address = Address::try_from_inner(pad_trit_buf(iota_bundle::ADDRESS_TRIT_LEN, tbits_to_tritbuf(link.appinst.tbits())))
            .map_err(|e| anyhow!("Bad tx address: {:?}.", e))?;
        let tx_tag = Tag::try_from_inner(pad_trit_buf(iota_bundle::TAG_TRIT_LEN, tbits_to_tritbuf(link.msgid.tbits())))
            .map_err(|e| anyhow!("Bad tx tag: {:?}.", e))?;


        let txs = block_on(get_bundles(self, tx_address, tx_tag));
        if !txs.is_err() {
            Ok(bundles_from_trytes(txs.unwrap())
                .into_iter()
                .map(|b| msg_from_bundle(&b, multi_branching))
                .collect())
        } else {
            Ok(Vec::new())
        }
    }
}
