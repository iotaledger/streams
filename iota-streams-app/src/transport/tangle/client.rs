use anyhow::{
    anyhow,
    ensure,
    Result,
};
use core::{
    cmp::Ordering,
    convert::{
        TryFrom,
        TryInto,
    },
};
#[cfg(not(feature = "async"))]
use smol::block_on;

use iota::{
    client as iota_client,
    ternary as iota_ternary,
};

use bee_crypto::ternary::Hash;
use bee_transaction::Vertex;

use bee_transaction::bundled::{
    Address, Bundle, BundledTransactionBuilder as TransactionBuilder, BundledTransactionField,
    BundledTransaction as Transaction, Index, Nonce, OutgoingBundleBuilder, Payload, Tag, Timestamp, Value, 
    PAYLOAD_TRIT_LEN, TAG_TRIT_LEN, ADDRESS_TRIT_LEN
};

use iota_streams_core::prelude::{
    String,
    ToString,
    Vec,
};

use crate::{
    message::BinaryMessage,
    transport::{
        tangle::*,
        *,
    },
};

const TRYTE_CHARS: &str = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";

fn pad_tritbuf(
    n: usize,
    mut s: iota_ternary::TritBuf<iota_ternary::T1B1Buf>,
) -> iota_ternary::TritBuf<iota_ternary::T1B1Buf> {
    if n > s.len() {
        for _ in 0..n - s.len() {
            s.push(iota_ternary::trit::Trit::zero());
        }
        s
    } else {
        s
    }
}

fn bytes_to_tritbuf(input: &[u8]) -> iota_ternary::TritBuf<iota_ternary::T1B1Buf> {
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

fn bytes_from_tritbuf(input: &iota_ternary::TritBuf<iota_ternary::T1B1Buf>) -> Vec<u8> {
    let trytes = input
        .chunks(3)
        .map(|trits| {
            let x = (i8::from(trits.get(0).unwrap()))
                + (i8::from(trits.get(1).unwrap())) * 3
                + (i8::from(trits.get(2).unwrap())) * 9;
            char::from(iota_ternary::Tryte::try_from(x).unwrap())
        })
        .collect::<String>();

    let mut bytes = Vec::new();
    for i in 0..trytes.len() / 2 {
        // get a trytes pair
        let char1 = trytes.get(i * 2..i * 2 + 1).unwrap();
        let char2 = trytes.get(i * 2 + 1..i * 2 + 2).unwrap();
        let first_value = TRYTE_CHARS.find(&char1.to_string()).unwrap();
        let second_value = TRYTE_CHARS.find(&char2.to_string()).unwrap();

        let value = first_value + second_value * 27;
        bytes.push(value as u8);
    }

    bytes.to_vec()
}

fn bytes_from_trits(buf: &iota_ternary::Trits<iota_ternary::T1B1>) -> Vec<u8> {
    bytes_from_tritbuf(&buf.encode())
}

fn cmp_trits(a: &iota_ternary::Trits<iota_ternary::T1B1>, b: &iota_ternary::Trits<iota_ternary::T1B1>) -> Ordering {
    a.iter().cmp(b.iter())
}

fn make_tx(tx_address: Address, tx_tag: Tag, tx_timestamp: Timestamp, tx_payload: Payload) -> TransactionBuilder {
    let tx_builder = TransactionBuilder::new();

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

fn make_bundle(
    address: &[u8],
    tag: &[u8],
    mut body: &[u8],
    timestamp: u64,
    trunk: Hash,
    branch: Hash,
) -> Result<Bundle> {
    let tx_address = Address::try_from_inner(pad_tritbuf(ADDRESS_TRIT_LEN, bytes_to_tritbuf(address)))
        .map_err(|e| anyhow!("Bad tx address: {:?}.", e))?;
    let tx_tag = Tag::try_from_inner(pad_tritbuf(TAG_TRIT_LEN, bytes_to_tritbuf(tag)))
        .map_err(|e| anyhow!("Bad tx tag: {:?}.", e))?;
    let tx_timestamp = Timestamp::try_from_inner(timestamp).map_err(|e| anyhow!("Bad tx timestamp: {:?}.", e))?;

    let mut bundle_builder = OutgoingBundleBuilder::default();
    while !body.is_empty() {
        let (payload_chunk, rest_of_body) = body.split_at(core::cmp::min(PAYLOAD_BYTES, body.len()));
        let payload_tritbuf = pad_tritbuf(PAYLOAD_TRIT_LEN, bytes_to_tritbuf(payload_chunk));
        let tx_payload = Payload::try_from_inner(payload_tritbuf)
            .map_err(|e| anyhow!("Failed to create payload chunk: {:?}.", e))?;
        bundle_builder.push(make_tx(
            tx_address.clone(),
            tx_tag.clone(),
            tx_timestamp.clone(),
            tx_payload,
        ));
        body = rest_of_body;
    }

    bundle_builder
        .seal()
        .map_err(|e| anyhow!("Failed to seal bundle: {:?}.", e))?
        .attach_remote(trunk, branch)
        .map_err(|e| anyhow!("Failed to attach bundle: {:?}.", e))?
        .build()
        .map_err(|e| anyhow!("Failed to build bundle: {:?}.", e))
}

/// Reconstruct valid bundles from trytes (returned by client's `get_trytes` method)
/// taking into account `addtess`, `tag` and `bundle` fields.
pub fn bundles_from_trytes(mut txs: Vec<Transaction>) -> Vec<Bundle> {
    txs.sort_by(|x, y| {
        // TODO: impl Ord for Address, Tag, Hash
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
                if bundle[0].address() == tx.address()
                    && bundle[0].tag() == tx.tag()
                    && bundle[0].bundle() == tx.bundle()
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
            // TODO: This needs a proper incoming bundle building implementation, but it is not currently available
            let mut bundle_builder = OutgoingBundleBuilder::default();
            let mut trunk = Hash::zeros();
            let mut branch = Hash::zeros();
            for tx in txs.into_iter() {
                let tx_builder = TransactionBuilder::new();

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
            }

            let bundle_builder = bundle_builder
                .seal()
                .map_err(|e| anyhow!("Failed to seal incoming bundle: {:?}.", e))
                .unwrap()
                .attach_remote(trunk, branch)
                .map_err(|e| anyhow!("Failed to attach bundle: {:?}.", e))
                .unwrap()
                .build()
                .map_err(|e| anyhow!("Failed to build incoming bundle: {:?}.", e))
                .unwrap();

            Some(bundle_builder)
        })
        .collect()
}

/// Reconstruct Streams Message from bundle. The input bundle is not checked (for validity of
/// the hash, consistency of indices, etc.). Checked bundles are returned by `bundles_from_trytes`.
pub fn msg_from_bundle<F>(bundle: &Bundle) -> TangleMessage<F> {
    // TODO: Check bundle is not empty.
    let tx = bundle.head();
    let appinst = AppInst::from(bytes_from_trits(tx.address().to_inner()).as_ref());
    let msgid = MsgId::from(bytes_from_trits(tx.tag().to_inner()).as_ref());
    let mut body = Vec::new();
    for tx in bundle.into_iter() {
        let mut payload = bytes_from_trits(tx.payload().to_inner());
        payload.resize(PAYLOAD_BYTES, 0);
        body.extend_from_slice(&payload);
    }

    let binary = BinaryMessage::new(TangleAddress { appinst, msgid }, body.into());
    // let timestamp: u64 = *(tx.timestamp() as *const iota::bundle::Timestamp) as *const u64;
    let timestamp: u64 = unsafe { core::mem::transmute(tx.timestamp().clone()) };

    TangleMessage { binary, timestamp }
}

/// As Streams Message are packed into a bundle, and different bundles can have the same hash
/// (as bundle hash is calcualted over some essense fields including `address`, `timestamp`
/// and not including `tag`, so different Messages may end up in bundles with the same hash.
/// This leads that it may not be possible to STREAMS Messages from bundle hash only.
/// So this function also takes into account `address` and `tag` fields.
/// As STREAMS Messages can have the same message id (ie. `tag`) it is advised that STREAMS Message
/// bundles have distinct nonces and/or timestamps.
pub fn msg_to_bundle<F>(
    msg: &BinaryMessage<F, TangleAddress>,
    timestamp: u64,
    trunk: Hash,
    branch: Hash,
) -> Result<Bundle> {
    make_bundle(
        msg.link.appinst.as_ref(),
        msg.link.msgid.as_ref(),
        &msg.body.bytes,
        timestamp,
        trunk,
        branch,
    )
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

fn handle_client_result<T>(result: iota_client::Result<T>) -> Result<T> {
    result.map_err(|err| anyhow!("Failed iota_client: {}", err))
}

async fn get_bundles(client: &iota_client::Client, tx_address: Address, tx_tag: Tag) -> Result<Vec<Transaction>> {
    let find_bundles = handle_client_result(
        client.find_transactions()
            .tags(&vec![tx_tag][..])
            .addresses(&vec![tx_address][..])
            .send()
            .await,
    )?;
    ensure!(!find_bundles.hashes.is_empty(), "Transaction hashes not found.");

    let get_resp = handle_client_result(client.get_trytes(&find_bundles.hashes).await)?;
    ensure!(!get_resp.trytes.is_empty(), "Transactions not found.");
    Ok(get_resp.trytes)
}

async fn send_trytes(client: &iota_client::Client, opt: &SendTrytesOptions, txs: Vec<Transaction>) -> Result<Vec<Transaction>> {
    let attached_txs = handle_client_result(
        client.send_trytes()
            .min_weight_magnitude(opt.min_weight_magnitude)
            .depth(opt.depth)
            .trytes(txs)
            .send()
            .await,
    )?;
    Ok(attached_txs)
}

pub async fn async_send_message_with_options<F>(client: &iota_client::Client, msg: &TangleMessage<F>, opt: &SendTrytesOptions) -> Result<()> {
    // TODO: Get trunk and branch hashes. Although, `send_trytes` should get these hashes.
    let trunk = Hash::zeros();
    let branch = Hash::zeros();
    let bundle = msg_to_bundle(&msg.binary, msg.timestamp, trunk, branch)?;
    // TODO: Get transactions from bundle without copying.
    let txs = bundle.into_iter().collect::<Vec<Transaction>>();
    // Ignore attached transactions.
    send_trytes(client, opt, txs).await?;
    Ok(())
}

pub async fn async_recv_messages<F>(client: &iota_client::Client, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
    let tx_address = Address::try_from_inner(pad_tritbuf(ADDRESS_TRIT_LEN, bytes_to_tritbuf(link.appinst.as_ref())))
        .map_err(|e| anyhow!("Bad tx address: {:?}.", e))?;
    let tx_tag = Tag::try_from_inner(pad_tritbuf(TAG_TRIT_LEN, bytes_to_tritbuf(link.msgid.as_ref())))
        .map_err(|e| anyhow!("Bad tx tag: {:?}.", e))?;

    match get_bundles(client, tx_address, tx_tag).await {
        Ok(txs) => Ok(bundles_from_trytes(txs)
            .into_iter()
            .map(|b| msg_from_bundle(&b))
            .collect()),
        Err(_) => Ok(Vec::new()), // Just ignore the error?
    }
}

#[cfg(not(feature = "async"))]
pub fn sync_send_message_with_options<F>(client: &iota_client::Client, msg: &TangleMessage<F>, opt: &SendTrytesOptions) -> Result<()> {
    block_on(async_send_message_with_options(client, msg, opt))
}

#[cfg(not(feature = "async"))]
pub fn sync_recv_messages<F>(client: &iota_client::Client, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
    block_on(async_recv_messages(client, link))
}

/// Stub type for iota_client::Client.  Removed: Copy, Default
#[derive(Clone)]
pub struct Client {
    send_opt: SendTrytesOptions,
    client: iota_client::Client,
}

impl Default for Client {
    // Creates a new instance which links to a node on localhost:14265
    fn default() -> Self {
        Self {
            send_opt: SendTrytesOptions::default(),
            client: iota_client::ClientBuilder::new().node("http://localhost:14265").unwrap().build().unwrap()
        }
    }
}

impl Client {
    // Create an instance of Client with a ready client and its send options
    pub fn new(options: SendTrytesOptions, client: iota_client::Client) -> Self {
        Self {
            send_opt: options,
            client: client
        }
    }
    
    // Create an instance of Client with a node pointing to the given URL
    pub fn new_from_url(url: &str) -> Self {
        Self {
            send_opt: SendTrytesOptions::default(),
            client: iota_client::ClientBuilder::new().node(url).unwrap().build().unwrap()
        }
    }

    pub fn add_node(&mut self, url: &str) -> Result<bool> {
        self.client.add_node(url).map_err(|e| anyhow!("iota_client error {}:", e))
    }
}

impl TransportOptions for Client {
    type SendOptions = SendTrytesOptions;
    fn get_send_options(&self) -> SendTrytesOptions {
        self.send_opt.clone()
    }
    fn set_send_options(&mut self, opt: SendTrytesOptions) {
        self.send_opt = opt;
    }

    type RecvOptions = ();
    fn get_recv_options(&self) -> () {}
    fn set_recv_options(&mut self, _opt: ()) {}
}

#[cfg(not(feature = "async"))]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Client {
    /// Send a Streams message over the Tangle with the current timestamp and default SendTrytesOptions.
    fn send_message(&mut self, msg: &TangleMessage<F>) -> Result<()> {
        sync_send_message_with_options(&self.client, msg, &self.send_opt)
    }

    /// Receive a message.
    fn recv_messages(&mut self, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
        sync_recv_messages(&self.client, link)
    }
}

#[cfg(feature = "async")]
#[async_trait]
impl<F> Transport<TangleAddress, TangleMessage<F>> for Client
where
    F: 'static + core::marker::Send + core::marker::Sync,
{
    /// Send a Streams message over the Tangle with the current timestamp and default SendTrytesOptions.
    async fn send_message(&mut self, msg: &TangleMessage<F>) -> Result<()> {
        async_send_message_with_options(&self.client, msg, &self.send_opt).await
    }

    /// Receive a message.
    async fn recv_messages(&mut self, link: &TangleAddress) -> Result<Vec<TangleMessage<F>>> {
        async_recv_messages(&self.client, link).await
    }

    async fn recv_message(&mut self, link: &TangleAddress) -> Result<TangleMessage<F>> {
        let mut msgs = self.recv_messages(link).await?;
        if let Some(msg) = msgs.pop() {
            ensure!(msgs.is_empty(), "More than one message found.");
            Ok(msg)
        } else {
            Err(anyhow!("Message not found."))
        }
    }
}
