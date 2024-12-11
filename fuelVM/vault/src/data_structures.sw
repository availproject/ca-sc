library;

use std::hash::{Hash, Hasher};

pub enum Method {
    Deposit: (),
    Settle: (),
}

impl<T> Hash for Vec<T> 
where
    T: Hash,
{
    fn hash(self, ref mut state: Hasher) {
        for element in self.iter() {
            element.hash(state);
        }
    }
}


pub struct SourcePair {
    pub chain_id: u256,
    pub asset_id: AssetId,
    pub value: u64,
}

impl Hash for SourcePair {
    fn hash(self, ref mut state: Hasher) {
        self.chain_id.hash(state);
        self.asset_id.hash(state);
        self.value.hash(state);
    }
}

pub struct DestinationPair {
    pub asset_id: AssetId,
    pub value: u64,
}

impl Hash for DestinationPair {
    fn hash(self, ref mut state: Hasher) {
        self.asset_id.hash(state);
        self.value.hash(state);
    }
}

pub struct Request {
    pub sources: Vec<SourcePair>,
    pub destination_chain_id: u256,
    pub destinations: Vec<DestinationPair>,
    pub nonce: u64,
    // FuelVM uses TAI64 timestamps
    pub expiry: u64,
}

impl Hash for Request {
    fn hash(self, ref mut state: Hasher) {
        self.sources.hash(state);
        self.destination_chain_id.hash(state);
        self.destinations.hash(state);
        self.nonce.hash(state);
        self.expiry.hash(state);
    }
}

pub struct SettleData {
    pub solvers: Vec<Address>,
    pub assets: Vec<AssetId>,
    pub amounts: Vec<u64>,
    pub nonce: u64,
}

impl Hash for SettleData {
    fn hash(self, ref mut state: Hasher) {
        self.solvers.hash(state);
        self.assets.hash(state);
        self.amounts.hash(state);
        self.nonce.hash(state);
    }
}
