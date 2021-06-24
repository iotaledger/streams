use core::fmt;

use iota_streams_app::identifier::Identifier;
use iota_streams_core::{
    errors::{
        err,
        error_messages::Errors::SignatureMismatch
    },
    prelude::{
        HashMap,
        Vec,
    },
    psk::{
        get_id_from_psk,
        Psk,
        PskId
    },
    Result,
    sponge::prp::PRP,
};
use iota_streams_core_edsig::key_exchange::x25519;

pub trait KeyStore<Info, F: PRP>: Default {
    fn filter(&self, pks: &[&Identifier]) -> Vec<(&Identifier, &Identifier)>;

    /// Retrieve the sequence state for a given publisher
    fn get(&self, id: &Identifier) -> Option<&Info>;
    fn get_mut(&mut self, id: &Identifier) -> Option<&mut Info>;
    fn get_ke_pk(&self, id: &Identifier) -> Option<&x25519::PublicKey>;
    fn get_psk(&self, id: &Identifier) -> Option<&Psk>;
    fn contains(&self, id: &Identifier) -> bool;
    fn insert_key(&mut self, id: Identifier, info: Info) -> Result<()>;
    fn get_next_pskid(&self) -> Option<&PskId>;
    fn keys(&self) -> Vec<(&Identifier, &Identifier)>;
    fn iter(&self) -> Vec<(&Identifier, &Info)>;
    fn iter_mut(&mut self) -> Vec<(&Identifier, &mut Info)>;
}

pub struct KeyMap<Info> {
    /// Map from user identity -- ed25519 pk -- to
    /// a precalculated corresponding x25519 pk and some additional info.
    keys: HashMap<Identifier, (Identifier, Info)>,
}

impl<Info> KeyMap<Info> {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }
}

impl<Info> Default for KeyMap<Info> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Info, F: PRP> KeyStore<Info, F> for KeyMap<Info> {
    fn filter(&self, pks: &[&Identifier]) -> Vec<(&Identifier, &Identifier)> {
        pks.iter()
            .filter_map(|id| self.keys.get_key_value(id).map(|(e, (x, _))| (e, x)))
            .collect()
    }

    fn get(&self, id: &Identifier) -> Option<&Info> {
        self.keys.get(id).map(|(_x, i)| i)
    }
    fn get_mut(&mut self, id: &Identifier) -> Option<&mut Info> {
        self.keys.get_mut(&id).map(|(_x, i)| i)
    }
    fn get_ke_pk(&self, id: &Identifier) -> Option<&x25519::PublicKey> {
        self.keys.get(&id)
            .filter(|(x, _i)| x.get_xpk().is_some())
            .map(|(x, _i)| x.get_xpk().unwrap())

    }

    fn get_psk(&self, id: &Identifier) -> Option<&Psk> {
        self.keys.get(&id)
            .filter(|(x, _i)| x.get_psk().is_some())
            .map(|(x, _i)| x.get_psk().unwrap())

    }

    fn get_next_pskid(&self) -> Option<&PskId> {
        let mut iter = self.keys.iter();
        loop {
            match iter.next() {
                Some((id, _store)) => {
                    if let Identifier::PskId(pskid) = id {
                        return Some(pskid)
                    }
                },
                None => return None
            }
        }
    }

    fn contains(&self, id: &Identifier) -> bool {
        self.keys.contains_key(id)
    }

    fn insert_key(&mut self, id: Identifier, info: Info) -> Result<()> {
        match &id {
            Identifier::EdPubKey(pk) => {
                let store_id = Identifier::XPubKey(x25519::public_from_ed25519(&pk.0)?.into());
                self.keys.insert(id, (store_id, info));
                Ok(())
            },
            Identifier::PskId(_pskid) => {
                self.keys.insert(id.clone(), (id, info));
                Ok(())
            },
            Identifier::Psk(psk) => {
                let pskid = Identifier::PskId(get_id_from_psk::<F>(psk));
                self.keys.insert(pskid, (id, info));
                Ok(())
            }
            _ => {
                println!("Signature mismatch in insert pk");
                err(SignatureMismatch)
            }
        }
    }

    fn keys(&self) -> Vec<(&Identifier, &Identifier)> {
        self.keys.iter().map(|(k, (x, _i))| (k, x)).collect()
    }

    fn iter(&self) -> Vec<(&Identifier, &Info)> {
        self.keys.iter().map(|(k, (_x, i))| (k, i)).collect()
    }
    fn iter_mut(&mut self) -> Vec<(&Identifier, &mut Info)> {
        self.keys.iter_mut().map(|(k, (_x, i))| (k, i)).collect()
    }
}

impl<Info: fmt::Display> fmt::Display for KeyMap<Info> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (k, (_x, i)) in self.keys.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(&k.to_bytes()), i)?;
        }
        Ok(())
    }
}
