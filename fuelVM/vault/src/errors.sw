library;

use ::data_structures::DestinationPair;

pub enum VaultError {
    /// Emitted when the deposited asset doesn't match the request.
    AssetMismatch: (),
    /// Emitted when the request's chain ID doesn't match that of Fuel Ignition.
    ChainIdMismatch: (),
    /// Emitted when the solver's transaction doesn't fill all of the request's destination pairs.
    DestinationPairsNotFilled: Vec<DestinationPair>,
    /// Emitted when the transaction performing a fill doesn't include an output that matches
    /// the requested destination pair.
    InvalidFillOutputs: (),
    /// Emitted when the address recovered from a signature doesn't match the target.
    InvalidSignature: (),
    /// Emitted when a nonce has already been used.
    NonceAlreadyUsed: (),
    /// Emitted when a request has expired.
    RequestExpired: (),
    /// Emitted when a request can't be verified due to a signature mismatch.
    RequestUnverified: (),
    /// Emitted when the number of solvers and amounts in a given [SettleData] don't match.
    SolversAndAmountsLengthMismatch: (),
    /// Emitted when the number of solvers and assets in a given [SettleData] don't match.
    SolversAndAssetsLengthMismatch: (),
    /// Emitted when the deposited amount doesn't match the request.
    ValueMismatch: (),
    /// Emitted when a suitable address could not be found in the party list
    AddressNotFound: (),
}
