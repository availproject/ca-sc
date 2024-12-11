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
    /// The chain ID of the source pair.
    pub chain_id: u256,
    /// The asset ID of the source pair.
    pub asset_id: AssetId,
    /// The value of the source pair.
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
    /// The asset ID of the destination pair.
    pub asset_id: AssetId,
    /// The value of the destination pair.
    pub value: u64,
}

impl Hash for DestinationPair {
    fn hash(self, ref mut state: Hasher) {
        self.asset_id.hash(state);
        self.value.hash(state);
    }
}

pub struct Request {
    /// The vector of source chain pairs for the request.
    pub sources: Vec<SourcePair>,
    /// The chain ID of the destination chain.
    pub destination_chain_id: u256,
    /// The vector of destination chain pairs.
    pub destinations: Vec<DestinationPair>,
    /// The nonce of the request.
    pub nonce: u64,
    /// The expiry timestamp for the request.
    ///
    /// # Additional Information
    /// FuelVM uses TAI64 timestamps
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
    /// The vector of solvers to be paid.
    pub solvers: Vec<Address>,
    /// The vector of assets ID for the assets to be paid.
    pub assets: Vec<AssetId>,
    /// The vector of amounts for the assets to be paid.
    pub amounts: Vec<u64>,
    /// The nonce of the settlement.
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
