use anyhow::{
    anyhow,
    ensure,
    Result,
};
use core::{
    cell::RefCell,
    fmt::Debug,
};

use iota_streams_core::{
    prelude::{
        vec,
        Vec,
    },
    prng,
    psk,
};
use iota_streams_core_edsig::{
    key_exchange::x25519,
    signature::ed25519,
};

use iota_streams_app::{
    message::{
        hdf::{
            FLAG_BRANCHING_MASK,
            HDF,
        },
        *,
    },
};
use iota_streams_ddml::{
    link_store::LinkStore,
    types::*,
};

use super::*;
use crate::message::*;

const ANN_MESSAGE_NUM: u64 = 0;
const SUB_MESSAGE_NUM: u64 = 0;
const SEQ_MESSAGE_NUM: u64 = 1;

pub struct User<F, Link, LG, LS, PKS, PSKS>
where
    F: PRP,
    Link: HasLink,
{
    /// PRNG object used for Ed25519, X25519, Spongos key generation, etc.
    #[allow(dead_code)]
    pub(crate) prng: prng::Prng<F>,

    /// Own Ed25519 private key.
    pub(crate) sig_kp: ed25519::Keypair,

    /// Own x25519 key pair corresponding to Ed25519 keypair.
    pub(crate) ke_kp: (x25519::StaticSecret, x25519::PublicKey),

    /// User' pre-shared keys.
    pub(crate) psk_store: PSKS,

    /// Users' trusted public keys together with additional sequencing info: (msgid, seq_num).
    pub(crate) pk_store: PKS,

    /// Author's Ed25519 public key.
    pub(crate) author_sig_pk: Option<ed25519::PublicKey>,

    /// Link generator.
    pub(crate) link_gen: LG,

    /// Link store.
    pub(crate) link_store: RefCell<LS>,

    /// Application instance - Link to the announce message.
    /// None if channel is not created or user is not subscribed.
    pub(crate) appinst: Option<Link>,

    /// Flags bit field
    pub flags: u8,

    pub message_encoding: Vec<u8>,

    pub uniform_payload_length: usize,
}

impl<F, Link, LG, LS, PKS, PSKS> User<F, Link, LG, LS, PKS, PSKS>
where
    F: PRP,
    Link: HasLink + AbsorbExternalFallback<F>,
    <Link as HasLink>::Base: Eq + Debug,
    <Link as HasLink>::Rel: Eq + Debug + SkipFallback<F> + AbsorbFallback<F>,
    LG: ChannelLinkGenerator<Link>,
    LS: LinkStore<F, <Link as HasLink>::Rel> + Default,
    PKS: PublicKeyStore<SequencingState<<Link as HasLink>::Rel>>,
    PSKS: PresharedKeyStore,
{
    /// Create a new User and generate Ed25519 key pair and corresponding X25519 key pair.
    pub fn gen(
        prng: prng::Prng<F>,
        nonce: Vec<u8>,
        flags: u8,
        message_encoding: Vec<u8>,
        uniform_payload_length: usize,
    ) -> Self {
        let sig_kp = ed25519::Keypair::generate(&mut prng::Rng::new(prng.clone(), nonce.clone()));
        let ke_kp = x25519::keypair_from_ed25519(&sig_kp);

        // App instance link is generated using the 32 byte PubKey and the first 8 bytes of the nonce
        // let mut appinst_input = Vec::new();
        // appinst_input.extend_from_slice(&sig_kp.public.to_bytes()[..]);
        // appinst_input.extend_from_slice(&nonce[0..8]);
        //
        // let appinst = link_gen.link_from((&appinst_input, &ke_kp.1, ANN_MESSAGE_NUM));

        // Start sequence state of new publishers to 2
        // 0 is used for Announce/Subscribe/Unsubscribe
        // 1 is used for sequence messages
        // let mut seq_map = HashMap::new();
        // seq_map.insert(ke_kp.1.as_bytes().to_vec(), (appinst.clone(), 2 as usize));

        Self {
            prng,
            sig_kp,
            ke_kp,

            psk_store: PSKS::default(),
            pk_store: PKS::default(),
            author_sig_pk: None,
            link_gen: LG::default(),
            link_store: RefCell::new(LS::default()),
            appinst: None,
            flags,
            message_encoding,
            uniform_payload_length,
        }
    }

    /// Create a new channel (without announcing it). User now becomes Author.
    pub fn create_channel(&mut self, channel_idx: u64) -> Result<()> {
        ensure!(
            self.appinst.is_none(),
            "Can't create channel: a channel already created/registered."
        );
        let appinst = self.link_gen.link_from((&self.sig_kp.public, channel_idx));
        self.pk_store.insert(
            self.sig_kp.public.clone(),
            SequencingState(appinst.rel().clone(), 2_u64),
        );
        self.appinst = Some(appinst);
        Ok(())
    }

    /// Prepare Announcement message.
    pub fn prepare_announcement<'a>(
        &'a mut self,
    ) -> Result<PreparedMessage<'a, F, Link, LS, announce::ContentWrap<F>>> {
        // Create HDF for the first message in the channel.
        let msg_link = self.link_gen.link_from(());
        let header = HDF::new(msg_link)
            .with_content_type(ANNOUNCE)?
            .with_payload_length(1)?
            .with_seq_num(ANN_MESSAGE_NUM);
        let content = announce::ContentWrap::new(&self.sig_kp, self.flags);
        Ok(PreparedMessage::new(self.link_store.borrow(), header, content))
    }

    /// Create Announce message.
    pub fn announce<'a>(
        &'a mut self,
    ) -> Result<WrappedMessage<F, Link>> {
        self.prepare_announcement()?.wrap()
    }

    pub fn commit_message<'a>(
        &'a mut self,
        msg: WrappedMessage<F, Link>,
        info: <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()>{
        msg.commit(self.link_store.borrow_mut(), info)?;
        Ok(())
    }

    pub fn unwrap_announcement<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, announce::ContentUnwrap<F>>> {
        if let Some(appinst) = &self.appinst {
            ensure!(
                appinst == &preparsed.header.link,
                "Got Announce with address {:?}, but already registered to a channel {:?}",
                preparsed.header.link.base(),
                appinst.base()
            );
        }

        let content = announce::ContentUnwrap::<F>::default();
        let r = preparsed.unwrap(&*self.link_store.borrow(), content);
        r
    }

    /// Bind Subscriber (or anonymously subscribe) to the channel announced
    /// in the message.
    pub fn handle_announcement<'a>(
        &mut self,
        msg: BinaryMessage<F, Link>,
        info: <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()> {
        let preparsed = msg.parse_header()?;
        ensure!(preparsed.content_type() == ANNOUNCE, "Message is not an announcement");

        let unwrapped = self.unwrap_announcement(preparsed)?;
        let link = unwrapped.link.clone();
        let content = unwrapped.commit(self.link_store.borrow_mut(), info)?;
        // TODO: check commit after message is done / before joined

        // TODO: Verify trust to Author's public key?
        // At the moment the Author is trusted unconditionally.

        // TODO: Verify appinst (address) == public key.
        // At the moment the Author is free to choose any address, not tied to PK.

        self.pk_store
            .insert(content.sig_pk.clone(), SequencingState(link.rel().clone(), 2_u64));
        self.pk_store
            .insert(self.sig_kp.public.clone(), SequencingState(link.rel().clone(), 2_u64));
        // Reset link_gen
        let _appinst = self.link_gen.link_from(link.clone());
        self.appinst = Some(link);
        self.author_sig_pk = Some(content.sig_pk);
        self.flags = content.flags.0;
        Ok(())
    }

    /// Prepare Subscribe message.
    pub fn prepare_subscribe<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
    ) -> Result<PreparedMessage<'a, F, Link, LS, subscribe::ContentWrap<'a, F, Link>>> {
        if let Some(author_sig_pk) = &self.author_sig_pk {
            if let Some(author_ke_pk) = self.pk_store.get_ke_pk(author_sig_pk) {
                let msg_link = self.link_gen.link_from((link_to, &self.sig_kp.public, SUB_MESSAGE_NUM));
                let header = HDF::new(msg_link)
                    .with_content_type(SUBSCRIBE)?
                    .with_payload_length(1)?
                    .with_seq_num(SUB_MESSAGE_NUM);
                let unsubscribe_key = NBytes::from(prng::random_key());
                let content = subscribe::ContentWrap {
                    link: link_to,
                    unsubscribe_key,
                    subscriber_sig_kp: &self.sig_kp,
                    author_ke_pk: author_ke_pk,
                    _phantom: core::marker::PhantomData,
                };
                Ok(PreparedMessage::new(self.link_store.borrow(), header, content))
            } else {
                Err(anyhow!("Internal error: author's key exchange public key not found."))
            }
        } else {
            Err(anyhow!("Subscriber doesn't have channel Author's x25519 public key."))
        }
    }

    /// Subscribe to the channel.
    pub fn subscribe(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
    ) -> Result<WrappedMessage<F, Link>> {
        self.prepare_subscribe(link_to)?.wrap()
    }

    pub fn unwrap_subscribe<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, subscribe::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = subscribe::ContentUnwrap::new(&self.ke_kp.0);
        preparsed.unwrap(&*self.link_store.borrow(), content)
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub fn handle_subscribe<'a>(
        &mut self,
        msg: BinaryMessage<F, Link>,
        info: <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()> {
        let preparsed = msg.parse_header()?;

        let content = self
            .unwrap_subscribe(preparsed)?
            .commit(self.link_store.borrow_mut(), info)?;
        // TODO: trust content.subscriber_sig_pk
        let subscriber_sig_pk = content.subscriber_sig_pk;
        let ref_link = self.appinst.as_ref().unwrap().rel().clone();
        self.pk_store
            .insert(subscriber_sig_pk, SequencingState(ref_link, SEQ_MESSAGE_NUM));
        // Unwrapped unsubscribe_key is not used explicitly.
        Ok(())
    }

    fn do_prepare_keyload<'a, Psks, KePks>(
        &'a self,
        header: HDF<Link>,
        link_to: &'a <Link as HasLink>::Rel,
        psks: Psks,
        ke_pks: KePks,
    ) -> Result<PreparedMessage<'a, F, Link, LS, keyload::ContentWrap<'a, F, Link, Psks, KePks>>>
    where
        Psks: Clone + ExactSizeIterator<Item = psk::IPsk<'a>>,
        KePks: Clone + ExactSizeIterator<Item = (ed25519::IPk<'a>, x25519::IPk<'a>)>,
    {
        let nonce = NBytes::from(prng::random_nonce());
        let key = NBytes::from(prng::random_key());
        let content = keyload::ContentWrap {
            link: link_to,
            nonce: nonce,
            key: key,
            psks: psks,
            ke_pks: ke_pks,
            sig_kp: &self.sig_kp,
            _phantom: core::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.link_store.borrow(), header, content))
    }

    pub fn prepare_keyload<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        psk_ids: &psk::PskIds,
        pks: &'a Vec<ed25519::PublicKey>,
    ) -> Result<
        PreparedMessage<
            'a,
            F,
            Link,
            LS,
            keyload::ContentWrap<
                'a,
                F,
                Link,
                vec::IntoIter<psk::IPsk<'a>>,
                vec::IntoIter<(ed25519::IPk<'a>, x25519::IPk<'a>)>,
            >,
        >,
    > {
        let seq_num = self.get_seq_num().ok_or(anyhow!("Internal error: bad seq num"))?;
        let msg_link = self.link_gen.link_from((link_to, &self.sig_kp.public, seq_num));
        let header = HDF::new(msg_link)
            .with_content_type(KEYLOAD)?
            .with_payload_length(1)?
            .with_seq_num(seq_num);
        let psks = self.psk_store.filter(psk_ids);
        let ke_pks = self.pk_store.filter(pks);
        self.do_prepare_keyload(header, link_to, psks.into_iter(), ke_pks.into_iter())
    }

    pub fn prepare_keyload_for_everyone<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
    ) -> Result<
        PreparedMessage<
            'a,
            F,
            Link,
            LS,
            keyload::ContentWrap<
                'a,
                F,
                Link,
                vec::IntoIter<(&'a psk::PskId, &'a psk::Psk)>,
                vec::IntoIter<(&'a ed25519::PublicKey, &'a x25519::PublicKey)>,
            >,
        >,
    > {
        let seq_num = self.get_seq_num().ok_or(anyhow!("Internal error: bad seq num"))?;
        let msg_link = self.link_gen.link_from((link_to, &self.sig_kp.public, seq_num));
        let header = hdf::HDF::new(msg_link)
            .with_content_type(KEYLOAD)?
            .with_payload_length(1)?
            .with_seq_num(seq_num);
        let ipsks = self.psk_store.iter();
        let ike_pks = self.pk_store.keys();
        self.do_prepare_keyload(header, link_to, ipsks.into_iter(), ike_pks.into_iter())
    }

    /// Create keyload message with a new session key shared with recipients
    /// identified by pre-shared key IDs and by NTRU public key IDs.
    pub fn share_keyload(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        psk_ids: &psk::PskIds,
        ke_pks: &Vec<ed25519::PublicKey>,
    ) -> Result<WrappedMessage<F, Link>> {
        self.prepare_keyload(link_to, psk_ids, ke_pks)?.wrap()
    }

    /// Create keyload message with a new session key shared with all Subscribers
    /// known to Author.
    pub fn share_keyload_for_everyone(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
    ) -> Result<WrappedMessage<F, Link>> {
        self.prepare_keyload_for_everyone(link_to)?.wrap()
    }

    fn lookup_psk<'b>(&'b self, pskid: &psk::PskId) -> Option<&'b psk::Psk> {
        self.psk_store.get(pskid)
    }

    fn lookup_ke_sk<'b>(&'b self, ke_pk: &ed25519::PublicKey) -> Option<&'b x25519::StaticSecret> {
        if self.sig_kp.public == *ke_pk {
            Some(&self.ke_kp.0)
        } else {
            None
        }
    }

    pub fn unwrap_keyload<'a, 'b>(
        &'b self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<
        UnwrappedMessage<
            F,
            Link,
            keyload::ContentUnwrap<
                'b,
                F,
                Link,
                Self,
                for<'c> fn(&'c Self, &psk::PskId) -> Option<&'c psk::Psk>,
                for<'c> fn(&'c Self, &ed25519::PublicKey) -> Option<&'c x25519::StaticSecret>,
            >,
        >,
    > {
        self.ensure_appinst(&preparsed)?;
        if let Some(ref author_sig_pk) = self.author_sig_pk {
            let content = keyload::ContentUnwrap::<
                    'b,
                F,
                Link,
                Self,
                for<'c> fn(&'c Self, &psk::PskId) -> Option<&'c psk::Psk>,
                for<'c> fn(&'c Self, &ed25519::PublicKey) -> Option<&'c x25519::StaticSecret>,
                >::new(self, Self::lookup_psk, Self::lookup_ke_sk, author_sig_pk);
            preparsed.unwrap(&*self.link_store.borrow(), content)
        } else {
            Err(anyhow!("Can't unwrap keyload, no author's public key"))
        }
    }

    /// Try unwrapping session key from keyload using Subscriber's pre-shared key or NTRU private key (if any).
    pub fn handle_keyload<'a>(
        &mut self,
        msg: BinaryMessage<F, Link>,
        info: <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<()> {
        let preparsed = msg.parse_header()?;

        let content = self
            .unwrap_keyload(preparsed)?
            .commit(self.link_store.borrow_mut(), info)?;
        // Unwrapped nonce and key in content are not used explicitly.
        // The resulting spongos state is joined into a protected message state.
        // Store any unknown publishers
        if let Some(appinst) = &self.appinst {
            for ke_pk in content.ke_pks {
                if self.pk_store.get(&ke_pk).is_none() {
                    // Store at state 2 since 0 and 1 are reserved states
                    self.pk_store.insert(ke_pk, SequencingState(appinst.rel().clone(), 2));
                }
            }
        }

        Ok(())
    }

    /// Prepare SignedPacket message.
    pub fn prepare_signed_packet<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        public_payload: &'a Bytes,
        masked_payload: &'a Bytes,
    ) -> Result<PreparedMessage<'a, F, Link, LS, signed_packet::ContentWrap<'a, F, Link>>> {
        let seq_num = self.get_seq_num().ok_or(anyhow!("Internal error: bad seq num"))?;
        let msg_link = self.link_gen.link_from((link_to, &self.sig_kp.public, seq_num));
        let header = HDF::new(msg_link)
            .with_content_type(SIGNED_PACKET)?
            .with_payload_length(1)?
            .with_seq_num(seq_num);
        let content = signed_packet::ContentWrap {
            link: link_to,
            public_payload: public_payload,
            masked_payload: masked_payload,
            sig_kp: &self.sig_kp,
            _phantom: core::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.link_store.borrow(), header, content))
    }

    /// Create a signed message with public and masked payload.
    pub fn sign_packet(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<WrappedMessage<F, Link>> {
        self.prepare_signed_packet(link_to, public_payload, masked_payload)?.wrap()
    }

    pub fn unwrap_signed_packet<'a>(
        &'a self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, signed_packet::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = signed_packet::ContentUnwrap::default();
        preparsed.unwrap(&*self.link_store.borrow(), content)
    }

    /// Verify new Author's MSS public key and update Author's MSS public key.
    pub fn handle_signed_packet<'a>(
        &'a mut self,
        msg: BinaryMessage<F, Link>,
        info: <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<(ed25519::PublicKey, Bytes, Bytes)> {
        // TODO: pass author_pk to unwrap
        let preparsed = msg.parse_header()?;

        let content = self
            .unwrap_signed_packet(preparsed)?
            .commit(self.link_store.borrow_mut(), info)?;
        Ok((content.sig_pk, content.public_payload, content.masked_payload))
    }

    /// Prepare TaggedPacket message.
    pub fn prepare_tagged_packet<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        public_payload: &'a Bytes,
        masked_payload: &'a Bytes,
    ) -> Result<PreparedMessage<'a, F, Link, LS, tagged_packet::ContentWrap<'a, F, Link>>> {
        let seq_num = self.get_seq_num().ok_or(anyhow!("Internal error: bad seq num"))?;
        let msg_link = self.link_gen.link_from((link_to, &self.sig_kp.public, seq_num));
        let header = HDF::new(msg_link)
            .with_content_type(TAGGED_PACKET)?
            .with_payload_length(1)?
            .with_seq_num(seq_num);
        let content = tagged_packet::ContentWrap {
            link: link_to,
            public_payload: public_payload,
            masked_payload: masked_payload,
            _phantom: core::marker::PhantomData,
        };
        Ok(PreparedMessage::new(self.link_store.borrow(), header, content))
    }

    /// Create a tagged (ie. MACed) message with public and masked payload.
    /// Tagged messages must be linked to a secret spongos state, ie. keyload or a message linked to keyload.
    pub fn tag_packet(
        &mut self,
        link_to: &<Link as HasLink>::Rel,
        public_payload: &Bytes,
        masked_payload: &Bytes,
    ) -> Result<WrappedMessage<F, Link>> {
        self.prepare_tagged_packet(link_to, public_payload, masked_payload)?.wrap()
    }

    pub fn unwrap_tagged_packet<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, tagged_packet::ContentUnwrap<F, Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = tagged_packet::ContentUnwrap::new();
        preparsed.unwrap(&*self.link_store.borrow(), content)
    }

    /// Get public payload, decrypt masked payload and verify MAC.
    pub fn handle_tagged_packet<'a>(
        &mut self,
        msg: BinaryMessage<F, Link>,
        info: <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<(Bytes, Bytes)> {
        let preparsed = msg.parse_header()?;

        let content = self
            .unwrap_tagged_packet(preparsed)?
            .commit(self.link_store.borrow_mut(), info)?;
        Ok((content.public_payload, content.masked_payload))
    }

    pub fn prepare_sequence<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        seq_num: u64,
        ref_link: &'a <Link as HasLink>::Rel,
    ) -> Result<PreparedMessage<'a, F, Link, LS, sequence::ContentWrap<'a, Link>>> {
        let msg_link = self.link_gen.link_from((link_to, &self.sig_kp.public, SEQ_MESSAGE_NUM));
        let header = HDF::new(msg_link)
            .with_content_type(SEQUENCE)?
            .with_payload_length(1)?
            .with_seq_num(SEQ_MESSAGE_NUM);

        let content = sequence::ContentWrap {
            link: link_to,
            pk: &self.sig_kp.public,
            seq_num,
            ref_link,
        };

        Ok(PreparedMessage::new(self.link_store.borrow(), header, content))
    }

    /*/// Send sequence message to show referenced message
    pub fn sequence<'a>(
        &'a mut self,
        link_to: &'a <Link as HasLink>::Rel,
        seq_num: u64,
        ref_link: &'a <Link as HasLink>::Rel,
        info: <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<WrappedMessage<F, Link>> {
        self.prepare_sequence(link_to, seq_num, ref_link)?.wrap()
    }*/

    pub fn send_sequence(
        &mut self,
        ref_link: &<Link as HasLink>::Rel,
    ) -> Result<Option<WrappedMessage<F, Link>>> {
        match self.pk_store.get_mut(&self.sig_kp.public) {
            Some(SequencingState(link_to, seq_num)) => {
                if (self.flags & FLAG_BRANCHING_MASK) != 0 {
                    let msg_link = self
                        .link_gen
                        .link_from((&*link_to, &self.sig_kp.public, SEQ_MESSAGE_NUM));
                    let header = HDF::new(msg_link)
                        .with_content_type(SEQUENCE)?
                        .with_payload_length(1)?
                        .with_seq_num(SEQ_MESSAGE_NUM);

                    let content = sequence::ContentWrap::<Link> {
                        link: link_to,
                        pk: &self.sig_kp.public,
                        seq_num: *seq_num,
                        ref_link,
                    };

                    let wrapped = {
                        let prepared = PreparedMessage::new(self.link_store.borrow(), header, content);
                        prepared.wrap()?
                    };

                    *link_to = wrapped.message.link.rel().clone();
                    *seq_num = *seq_num + 1;
                    Ok(Some(wrapped))
                } else {
                    let seq_num = *seq_num;
                    self.store_state_for_all(ref_link.clone(), seq_num);
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub fn unwrap_sequence<'a>(
        &self,
        preparsed: PreparsedMessage<'a, F, Link>,
    ) -> Result<UnwrappedMessage<F, Link, sequence::ContentUnwrap<Link>>> {
        self.ensure_appinst(&preparsed)?;
        let content = sequence::ContentUnwrap::default();
        preparsed.unwrap(&*self.link_store.borrow(), content)
    }

    // Fetch unwrapped sequence message to fetch referenced message
    pub fn handle_sequence<'a>(
        &mut self,
        msg: BinaryMessage<F, Link>,
        info: <LS as LinkStore<F, <Link as HasLink>::Rel>>::Info,
    ) -> Result<sequence::ContentUnwrap<Link>> {
        let preparsed = msg.parse_header()?;
        let content = self
            .unwrap_sequence(preparsed)?
            .commit(self.link_store.borrow_mut(), info)?;
        Ok(content)
    }

    pub fn is_multi_branching(&self) -> bool {
        (self.flags & FLAG_BRANCHING_MASK) != 0
    }

    // TODO: own seq_num should be stored outside of pk_store to avoid lookup and Option
    pub fn get_seq_num(&self) -> Option<u64> {
        self.pk_store
            .get(&self.sig_kp.public)
            .map(|SequencingState(_link, seq_num)| *seq_num)
    }

    pub fn ensure_appinst<'a>(&self, preparsed: &PreparsedMessage<'a, F, Link>) -> Result<()> {
        ensure!(self.appinst.is_some(), "No channel registered.");
        ensure!(
            self.appinst.as_ref().unwrap().base() == preparsed.header.link.base(),
            "Bad message application instance."
        );
        Ok(())
    }

    fn gen_next_msg_id(
        ids: &mut Vec<(ed25519::PublicKey, SequencingState<Link>)>,
        link_gen: &mut LG,
        pk_info: (&ed25519::PublicKey, &mut SequencingState<<Link as HasLink>::Rel>),
        branching: bool,
    ) {
        let (pk, SequencingState(seq_link, seq_num)) = pk_info;
        if branching {
            let msg_id = link_gen.link_from((&*seq_link, pk, 1_u64));
            ids.push((pk.clone(), SequencingState(msg_id, 1)));
        } else {
            let msg_id = link_gen.link_from((&*seq_link, pk, *seq_num));
            let msg_id1 = link_gen.link_from((&*seq_link, pk, *seq_num - 1));
            ids.push((pk.clone(), SequencingState(msg_id, *seq_num)));
            ids.push((pk.clone(), SequencingState(msg_id1, *seq_num - 1)));
        }
    }

    pub fn gen_next_msg_ids(&mut self, branching: bool) -> Vec<(ed25519::PublicKey, SequencingState<Link>)> {
        let mut ids = Vec::new();

        // TODO: Do the same for self.sig_kp.public
        for pk_info in self.pk_store.iter_mut() {
            Self::gen_next_msg_id(&mut ids, &mut self.link_gen, pk_info, branching);
        }
        ids
    }

    pub fn store_state(&mut self, pk: ed25519::PublicKey, link: <Link as HasLink>::Rel) {
        let seq_num = self.pk_store.get(&pk).unwrap().1;
        self.pk_store.insert(pk, SequencingState(link, seq_num + 1));
    }

    pub fn store_state_for_all(&mut self, link: <Link as HasLink>::Rel, seq_num: u64) {
        self.pk_store
            .insert(self.sig_kp.public.clone(), SequencingState(link.clone(), seq_num + 1));
        for (_pk, SequencingState(l, s)) in self.pk_store.iter_mut() {
            *l = link.clone();
            *s = seq_num + 1;
        }
    }
}
