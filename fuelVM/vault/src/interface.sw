library;

use ::data_structures::{Request, SettleData};
use std::b512::B512;

abi ArcanaVault {
    #[storage(read, write)]
    fn initialize_vault();

    #[payable]
    #[storage(read, write)]
    fn deposit(
        request: Request,
        signature: B512,
        from: Address,
        chain_index: u64,
    );

    #[storage(read, write)]
    fn fill(request: Request, signature: B512, from: Address);

    #[storage(read)]
    fn withdraw(to: Identity, asset_id: AssetId, amount: u64);

    #[storage(read, write)]
    fn settle(settle_data: SettleData, signature: B512);

    #[storage(read)]
    fn requests(signed_message_hash: b256) -> Option<b256>;

    #[storage(read)]
    fn deposit_nonce(nonce: u64) -> Option<bool>;

    #[storage(read)]
    fn fill_nonce(nonce: u64) -> Option<bool>;

    #[storage(read)]
    fn settle_nonce(nonce: u64) -> Option<bool>;
}
