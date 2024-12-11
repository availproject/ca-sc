library;

use ::data_structures::{Method, Request};

pub struct Deposit {
    pub from: Address,
    pub signed_message_hash: b256,
    pub request_hash: b256,
    pub request: Request,
}

pub struct Fill {
    pub from: Address,
    pub signed_message_hash: b256,
    pub solver: Address,
    pub request_hash: b256,
    pub request: Request,
}

pub struct Withdraw {
    pub to: Identity,
    pub asset_id: AssetId,
    pub amount: u64,
}

pub struct Settle {
    pub solver: Address,
    pub asset_id: AssetId,
    pub amount: u64,
    pub nonce: u64,
}
