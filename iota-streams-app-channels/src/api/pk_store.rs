use core::fmt;
use iota_streams_core::Result;

use iota_streams_core::{
    prelude::{
        HashMap,
        Vec,
    },
    psk::{
        Psk,
        PskId
    },
    errors::{
        err,
        error_messages::Errors::SignatureMismatch
    }
};
use iota_streams_core_edsig::{
    key_exchange::x25519::{
        self,
        PublicKeyWrap as XPubKeyWrap,
    },
    signature::ed25519::{
        self,
        PublicKeyWrap as EPubKeyWrap
    },
};

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum Identifier {
    EdPubKey(EPubKeyWrap),
    XPubKey(XPubKeyWrap),
    PskId(PskId),
    Psk(Psk),
}

impl Identifier {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Identifier::XPubKey(id) => id.0.as_bytes().to_vec(),
            Identifier::EdPubKey(id) => id.0.as_bytes().to_vec(),
            Identifier::PskId(id) => id.to_vec(),
            Identifier::Psk(id) => id.to_vec()
        }
    }

    pub fn get_pk(&self) -> Option<&ed25519::PublicKey> {
        if let Identifier::EdPubKey(pk) = self { Some(&pk.0) } else { None }
    }

    pub fn get_xpk(&self) -> Option<&x25519::PublicKey> {
        if let Identifier::XPubKey(xpk) = self { Some(&xpk.0) } else { None }
    }

    pub fn get_pskid(&self) -> Option<&PskId> {
        if let Identifier::PskId(id) = self { Some(id) } else { None }
    }
}


pub trait KeyStore<Info>: Default {
    fn filter(&self, pks: &[&Identifier]) -> Vec<(&Identifier, &Identifier)>;

    /// Retrieve the sequence state for a given publisher
    fn get(&self, id: &Identifier) -> Option<&Info>;
    fn get_mut(&mut self, id: &Identifier) -> Option<&mut Info>;
    fn get_ke_pk(&self, id: &Identifier) -> Option<&x25519::PublicKey>;
    fn insert(&mut self, id: Identifier, info: Info) -> Result<()>;
    //fn pub_keys(&self) -> Vec<(&ed25519::PublicKey, &x25519::PublicKey)>;
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

impl<Info> KeyStore<Info> for KeyMap<Info> {
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

    fn insert(&mut self, id: Identifier, info: Info) -> Result<()> {
        let store_id = match id.clone() {
            Identifier::EdPubKey(id) => {
                Ok(
                    Identifier::XPubKey(x25519::public_from_ed25519(&id.0)?.into())
                )
            },
            Identifier::PskId(id) => Ok(Identifier::PskId(id)),
            _ => err(SignatureMismatch),
        }?;

        self.keys.insert(id, (store_id, info));
        Ok(())
    }
/*    fn pub_keys(&self) -> Result<Vec<(&ed25519::PublicKey, &x25519::PublicKey)>> {
        let pks = self.keys.iter()
            .filter(|(k, (x, _i))| if let Identifier::EdPubKey(_pk) = k { true } else { false })
            .map(|(k, (x, _i))| (&k.get_pk()?, &x.get_xpk()?))
            .collect();
        Ok(pks)
    }*/
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
