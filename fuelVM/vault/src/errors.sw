library;

pub enum VaultError {
    RequestUnverified: (),
    ChainIdMismatch: (),
    NonceAlreadyUsed: (),
    AssetMismatch: (),
    InvalidFillOutputs: (),
    InvalidSignature: (),
    SolversAndAssetsLengthMismatch: (),
    SolversAndAmountsLengthMismatch: (),
    RequestExpired: (),
    ValueMismatch: (),
}
