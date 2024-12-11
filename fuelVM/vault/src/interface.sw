library;

use ::data_structures::{Request, SettleData};
use std::b512::B512;

abi ArcanaVault {
    /// Initializes the vault, setting privileged roles.
    ///
    /// # Additional Information
    ///
    /// This method can only be called once.
    ///
    /// # Reverts
    ///
    /// * When ownership has been set before.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `1`
    /// * Writes: `1`
    #[storage(read, write)]
    fn initialize_vault();

    /// Takes a deposit for the given request.
    ///
    /// # Arguments
    ///
    /// * `request`: [Request] - The user's request.
    /// * `signature`: [B512] - The signature over the `request`.
    /// * `from`: [Address] - The signer of the `request`.
    /// * `chain_index`: [u64] - The index of the source data.
    ///
    /// This method verifies the given request against the given signature.
    ///
    /// # Reverts
    ///
    /// * When the `request` chain ID doesn't match `FUEL_IGNITION_CHAIN_ID`.
    /// * When the `request` has expired.
    /// * When the asset deposited doesn't match the asset in the `request`.
    /// * When the amount of asset deposited doesn't match the amount of asset in the `request`.
    /// * When the nonce of the `request` is already used.
    /// * When the `request` could not be verified.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `1`
    /// * Writes: `2`
    #[payable]
    #[storage(read, write)]
    fn deposit(
        request: Request,
        signature: B512,
        from: Address,
        chain_index: u64,
    );

    /// Verifies that a request has been filled.
    ///
    /// # Additional Information
    ///
    /// The solver calling this method must have included outputs in the transaction that satisfy the `request` destination data.
    ///
    /// * `request`: [Request] - The user's request.
    /// * `signature`: [B512] - The signature over the `request`.
    /// * `from`: [Address] - The signer of the `request`.
    ///
    /// # Reverts
    ///
    /// * When the `request` chain ID doesn't match `FUEL_IGNITION_CHAIN_ID`.
    /// * When the `request` has expired.
    /// * When the there aren't enough transaction outputs to satisfy the `request`.
    /// * When a transaction output doesn't match the corresponding destination pair or receiver.
    /// * When the nonce of the `request` is already used.
    /// * When the `request` could not be verified.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `1`
    /// * Writes: `2`
    #[storage(read, write)]
    fn fill(request: Request, signature: B512, from: Address);

    /// Withdraw assets from the contract.
    ///
    /// # Additional Information
    ///
    /// Only callable by the contract owner.
    ///
    /// # Arguments
    ///
    /// * `to`: [Identity] - The recipient of the withdrawal.
    /// * `asset_id`: [AssetId] - The asset to withdraw.
    /// * `amount`: [u64] - The amount withdraw.
    ///
    /// # Reverts
    ///
    /// * When not called by the owner.
    /// * When reentrency occurs.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `1`
    #[storage(read)]
    fn withdraw(to: Identity, asset_id: AssetId, amount: u64);

    /// Pay solvers for verified work.
    ///
    /// # Additional Information
    ///
    /// Anyone can call this method as it checks if the `settle_data` was signed by the contract owner,
    /// if so the `settle_data` is considered valid.
    ///
    /// # Arguments
    ///
    /// * `settle_data`: [SettleData] - The data of each transfer to a solver.
    /// * `signature`: [B512] - The signature used to verify that the contract owner signed the given `settle_data`.
    ///
    /// # Reverts
    ///
    /// * When reentrency occurs.
    /// * When the number of solvers and assets in the `settle_data` don't match.
    /// * When the number of solvers and amounts in the `settle_data` don't match.
    /// * When the recovered address doesn't match the contract owner's address.
    /// * When the nonce of the `settle_data` is already used.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `1`
    /// * Writes: `1`
    #[storage(read, write)]
    fn settle(settle_data: SettleData, signature: B512);

    /// Gets a request hash from it's associated `signed_message_hash`
    ///
    /// # Arguments
    ///
    /// * `signed_message_hash`: [b256] - The hash of the EIP-191 signature of a hashed request.
    ///
    /// # Returns
    ///
    /// * [Option<b256>] - The hash of a request.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `1`
    #[storage(read)]
    fn requests(signed_message_hash: b256) -> Option<b256>;

    /// Gets a bool describing whether a given nonce has been used in a deposit
    ///
    /// # Arguments
    ///
    /// * `nonce`: [u64] - The nonce of a deposit.
    ///
    /// # Returns
    ///
    /// * [Option<bool>] - Whether a given nonce has been used in a deposit.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `1`
    #[storage(read)]
    fn deposit_nonce(nonce: u64) -> Option<bool>;

    /// Gets a bool describing whether a given nonce has been used in a fill
    ///
    /// # Arguments
    ///
    /// * `nonce`: [u64] - The nonce of a fill.
    ///
    /// # Returns
    ///
    /// * [Option<bool>] - Whether a given nonce has been used in a fill.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `1`
    #[storage(read)]
    fn fill_nonce(nonce: u64) -> Option<bool>;

    /// Gets a bool describing whether a given nonce has been used in a settlement
    ///
    /// # Arguments
    ///
    /// * `nonce`: [u64] - The nonce of a settlement.
    ///
    /// # Returns
    ///
    /// * [Option<bool>] - Whether a given nonce has been used in a settlement.
    ///
    /// # Number of Storage Accesses
    ///
    /// * Reads: `1`
    #[storage(read)]
    fn settle_nonce(nonce: u64) -> Option<bool>;
}
