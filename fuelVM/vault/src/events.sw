library;

use ::data_structures::{Method, Request};

/// Logged when a deposit is made.
pub struct Deposit {
    /// The signer of the [Request].
    pub from: Address,
    /// The EIP-191 signed hash of the [Request].
    pub signed_message_hash: b256,
    /// The hash of the [Request].
    pub request_hash: b256,
    /// The [Request] associated with the deposit.
    pub request: Request,
}

/// Logged when a request is filled.
pub struct Fill {
    /// The signer of the [Request].
    pub from: Address,
    /// The EIP-191 signed hash of the [Request].
    pub signed_message_hash: b256,
    /// The address that filled the [Request]
    pub solver: Address,
    /// The hash of the [Request].
    pub request_hash: b256,
    /// The [Request] associated with the deposit.
    pub request: Request,
}

/// Logged when a withdraw is made.
pub struct Withdraw {
    /// The recipient of the withdrawal.
    pub to: Identity,
    /// The asset ID of the withdrawn asset.
    pub asset_id: AssetId,
    /// The amount to withdraw.
    pub amount: u64,
}

/// Logged when a settlement is made.
pub struct Settle {
    /// The address that filled a [Request].
    pub solver: Address,
    /// The asset ID of the asset to send the `solver`.
    pub asset_id: AssetId,
    /// The amount of the asset to send the `solver`.
    pub amount: u64,
    /// The nonce of the settlement.
    pub nonce: u64,
}
