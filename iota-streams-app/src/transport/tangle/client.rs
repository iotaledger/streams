use chrono::Utc;
use failure::{bail, Fallible};
use std::convert::TryInto;
use std::str::FromStr;
use std::string::ToString;

use iota_constants::HASH_TRINARY_SIZE as HASH_LENGTH;
use iota_conversion::Trinary;
use iota_lib_rs::prelude::{iota_client, iota_constants, iota_conversion, iota_crypto, iota_model};

use iota_streams_core::tbits::{
    word::{BasicTbitWord, StringTbitWord},
    TbitSlice, Tbits,
};

use crate::transport::{tangle::*, *};

fn make_empty_tx() -> iota_model::Transaction {
    //8019
    let mut tx = iota_model::Transaction::default();
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

fn make_tx<TW>(
    address: &Tbits<TW>,
    tag: &Tbits<TW>,
    msg: &Tbits<TW>,
    timestamp: i64,
) -> iota_model::Transaction
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

fn make_txs<TW>(
    address: &Tbits<TW>,
    tag: &Tbits<TW>,
    msg: &Tbits<TW>,
    timestamp: i64,
) -> Vec<iota_model::Transaction>
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
pub fn bundle_to_trytes(bundle: &iota_model::Bundle) -> Vec<iota_conversion::Trytes> {
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
fn calc_bundle_hash(bundle: &iota_model::Bundle) -> Fallible<String> {
    use iota_crypto::{Kerl, Sponge};
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
fn check_bundle_hash(bundle: &iota_model::Bundle) -> Fallible<()> {
    failure::ensure!(!bundle.is_empty());
    let hash = calc_bundle_hash(bundle)?;
    let mut current_index = 0usize;
    let last_index = bundle.len() - 1;
    for tx in bundle.iter() {
        failure::ensure!(tx.current_index == current_index);
        failure::ensure!(tx.last_index == last_index);
        failure::ensure!(tx.bundle == hash);
        current_index += 1;
    }
    Ok(())
}

/// Reconstruct valid bundles from trytes (returned by client's `get_trytes` method)
/// taking into account `addtess`, `tag` and `bundle` fields.
pub fn bundles_from_trytes(trytes: &Vec<iota_conversion::Trytes>) -> Vec<iota_model::Bundle> {
    let mut txs = trytes
        .into_iter()
        .filter_map(|t| t.parse().ok())
        .collect::<Vec<iota_model::Transaction>>();

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
                if bundle[0].address == tx.address
                    && bundle[0].tag == tx.tag
                    && bundle[0].bundle == tx.bundle
                {
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
            let bundle = iota_model::Bundle::new(txs);
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
pub fn msg_to_bundle<TW, F>(
    msg: &TbinaryMessage<TW, F, TangleAddress<TW>>,
    timestamp: i64,
) -> iota_model::Bundle
where
    TW: StringTbitWord,
{
    let mut bundle = iota_model::Bundle::new(make_txs(
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
pub fn msg_from_bundle<TW, F>(
    bundle: &iota_model::Bundle,
) -> TbinaryMessage<TW, F, TangleAddress<TW>>
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
        TbinaryMessage::<TW, F, TangleAddress<TW>>::new(
            TangleAddress::<TW>::new(appinst.clone(), msgid),
            body,
        )
    };
    // A,N,[F,G]
    let m2 = {
        let msgid = MsgId {
            id: NTrytes(Tbits::<TW>::cycle_str(MSGID_SIZE, "N")),
        };
        let body = &Tbits::<TW>::cycle_str(6561, "F") + &Tbits::<TW>::cycle_str(6561, "G");
        TbinaryMessage::<TW, F, TangleAddress<TW>>::new(
            TangleAddress::<TW>::new(appinst.clone(), msgid),
            body,
        )
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
            (n1.link() == m1.link()
                && n1.body == m1.body
                && n2.link() == m2.link()
                && n2.body == m2.body)
                || (n1.link() == m2.link()
                    && n1.body == m2.body
                    && n2.link() == m1.link()
                    && n2.body == m1.body)
        );
    }
}

#[cfg(test)]
#[test]
fn test_bundle_from_to_trytes() {
    use iota_streams_core::{sponge::prp::troika::Troika, tbits::trinary::Trit};
    bundle_from_to_trytes::<Trit, Troika>();
}

impl<'a, TW, F> Transport<TW, F, TangleAddress<TW>> for iota_client::Client<'a>
where
    TW: StringTbitWord,
{
    /// Send a Streams message over the Tangle with the current timestamp and default SendTrytesOptions.
    fn send_message(&mut self, msg: &TbinaryMessage<TW, F, TangleAddress<TW>>) -> Fallible<()> {
        let opt = iota_client::options::SendTrytesOptions::default();
        //TODO: Decrease mwm?
        let timestamp = Utc::now().timestamp_millis();
        let bundle = msg_to_bundle(msg, timestamp);
        let trytes = bundle_to_trytes(&bundle);
        // Ignore PoWed transactions.
        let _txs = self.send_trytes(&trytes, opt)?;
        Ok(())
    }

    /// Receive a message.
    fn recv_message(
        &mut self,
        link: &TangleAddress<TW>,
    ) -> Fallible<Vec<TbinaryMessage<TW, F, TangleAddress<TW>>>> {
        let find_opt = iota_client::options::FindTransactionsOptions {
            bundles: Vec::new(),
            addresses: vec![link.appinst.to_string()],
            tags: vec![link.msgid.to_string()],
            approvees: Vec::new(),
        };

        let find_resp = self.find_transactions(find_opt)?;
        if let Some(e) = find_resp.error() {
            bail!("Find transactions failed with: {}.", e)
        } else if let Some(hashes) = find_resp.take_hashes() {
            let get_resp = self.get_trytes(&hashes)?;
            if let Some(e) = get_resp.error() {
                bail!("Get trytes failed with: {}.", e)
            } else if let Some(trytes) = get_resp.take_trytes() {
                return Ok(bundles_from_trytes(&trytes)
                    .into_iter()
                    .map(|bundle| msg_from_bundle(&bundle))
                    .collect());
            } else {
                bail!("Get trytes contains no trytes.")
            }
        } else {
            bail!("Find transactions contains no hashes.")
        }
    }
}
