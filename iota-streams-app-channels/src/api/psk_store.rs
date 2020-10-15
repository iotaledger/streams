use iota_streams_core::{
    prelude::{
        HashMap,
        Vec,
    },
    psk,
};

pub trait PresharedKeyStore: Default {
    fn insert(&mut self, pskid: psk::PskId, psk: psk::Psk);
    fn filter<'a>(&'a self, psk_ids: &'_ psk::PskIds) -> Vec<psk::IPsk<'a>>;
    fn get<'a>(&'a self, pskid: &'_ psk::PskId) -> Option<&'a psk::Psk>;
    fn iter(&self) -> Vec<(&psk::PskId, &psk::Psk)>;
}

#[derive(Default)]
pub struct PresharedKeyMap {
    psks: HashMap<psk::PskId, psk::Psk>,
}

impl PresharedKeyStore for PresharedKeyMap {
    fn insert(&mut self, pskid: psk::PskId, psk: psk::Psk) {
        self.psks.insert(pskid, psk);
    }
    fn filter<'a>(&'a self, psk_ids: &'_ psk::PskIds) -> Vec<psk::IPsk<'a>> {
        psk_ids
            .iter()
            .filter_map(|psk_id| self.psks.get_key_value(psk_id))
            .collect()
    }
    fn get<'a>(&'a self, pskid: &'_ psk::PskId) -> Option<&'a psk::Psk> {
        self.psks.get(pskid)
    }
    fn iter(&self) -> Vec<(&psk::PskId, &psk::Psk)> {
        self.psks.iter().collect()
    }
}
