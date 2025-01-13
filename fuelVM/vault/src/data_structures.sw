library;

use std::hash::{Hash, Hasher};

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
    pub nonce: u256,
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

pub struct StorableRequest {
    /// The chain ID of the destination chain.
    pub destination_chain_id: u256,
    /// The nonce of the request.
    pub nonce: u256,
    /// The expiry timestamp for the request.
    ///
    /// # Additional Information
    /// FuelVM uses TAI64 timestamps
    pub expiry: u64,
}

impl From<Request> for StorableRequest {
    fn from(request: Request) -> Self {
        Self {
            destination_chain_id: request.destination_chain_id,
            nonce: request.nonce,
            expiry: request.expiry,
        }
    }
}

impl From<StorableRequest> for Request {
    fn from(storable_request: StorableRequest) -> Self {
        Self {
            sources: Vec::new(),
            destination_chain_id: storable_request.destination_chain_id,
            destinations: Vec::new(),
            nonce: storable_request.nonce,
            expiry: storable_request.expiry,
        }
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
    pub nonce: u256,
}

impl Hash for SettleData {
    fn hash(self, ref mut state: Hasher) {
        self.solvers.hash(state);
        self.assets.hash(state);
        self.amounts.hash(state);
        self.nonce.hash(state);
    }
}
