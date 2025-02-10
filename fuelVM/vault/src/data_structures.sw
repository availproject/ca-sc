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

pub enum Universe {
    ETHEREUM: (),
    FUEL: (),
    SOLANA: (),
}

impl Universe {
    pub fn as_u8(self) -> u8 {
        match self {
            Universe::ETHEREUM => {
                return 0;
            },
            Universe::FUEL => {
                return 1;
            },
            Universe::SOLANA => {
                return 2;
            },
        }
    }
}

impl Hash for Universe {
    fn hash(self, ref mut state: Hasher) {
        self.as_u8().hash(state);
    }
}

pub struct Party {
    pub universe: Universe,
    pub address: Address,
}

impl Hash for Party {
    fn hash(self, ref mut state: Hasher) {
        self.universe.hash(state);
        self.address.hash(state);
    }
}

pub struct SourcePair {
    pub universe: Universe,
    /// The chain ID of the source pair.
    pub chain_id: u256,
    /// The asset ID of the source pair.
    pub asset_id: AssetId,
    /// The value of the source pair.
    pub value: u64,
}

impl Hash for SourcePair {
    fn hash(self, ref mut state: Hasher) {
        self.universe.hash(state);
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
    /// The destination universe of this request
    pub destination_universe: Universe,
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
    // The set of parties involved in this request
    pub parties: Vec<Party>,
}

impl Hash for Request {
    fn hash(self, ref mut state: Hasher) {
        self.sources.hash(state);
        self.destination_universe.hash(state);
        self.destination_chain_id.hash(state);
        self.destinations.hash(state);
        self.nonce.hash(state);
        self.expiry.hash(state);
        self.parties.hash(state);
    }
}

pub struct StorableRequest {
    pub destination_universe: Universe,
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
            destination_universe: request.destination_universe,
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
            destination_universe: storable_request.destination_universe,
            destination_chain_id: storable_request.destination_chain_id,
            destinations: Vec::new(),
            nonce: storable_request.nonce,
            expiry: storable_request.expiry,
            parties: Vec::new(),
        }
    }
}

pub struct SettleData {
    /// The universe of the settlement
    pub universe: Universe,
    /// The chain ID of the settlement
    pub chain_id: u256,
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
        self.universe.hash(state);
        self.chain_id.hash(state);
        self.solvers.hash(state);
        self.assets.hash(state);
        self.amounts.hash(state);
        self.nonce.hash(state);
    }
}
