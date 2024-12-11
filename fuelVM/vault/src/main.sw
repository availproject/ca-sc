contract;

mod interface;
pub mod data_structures;
mod events;
mod personal_sign_hash;
mod errors;

use interface::ArcanaVault;
use data_structures::{Method, Request, SettleData};
use personal_sign_hash::personal_sign_hash;
use errors::VaultError;
use events::{Deposit, Fill, Settle, Withdraw};

use sway_libs::{ownership::{_owner, initialize_ownership, only_owner}, reentrancy::*};
use standards::src5::{SRC5, State};

use std::{
    asset::transfer,
    b512::B512,
    block::timestamp,
    call_frames::msg_asset_id,
    context::msg_amount,
    ecr::ec_recover_address,
    hash::{
        Hash,
        keccak256,
    },
    outputs::{
        output_amount,
        output_asset_id,
        output_asset_to,
        output_count,
    },
};

configurable {
    INITIAL_OWNER: Identity = Identity::Address(Address::zero()),
    FUEL_IGNITION_CHAIN_ID: u256 = 9889,
}

storage {
    V1 {
        requests: StorageMap<b256, b256> = StorageMap {},
        deposit_nonce: StorageMap<u64, bool> = StorageMap {},
        fill_nonce: StorageMap<u64, bool> = StorageMap {},
        settle_nonce: StorageMap<u64, bool> = StorageMap {},
    },
}

impl SRC5 for Contract {
    #[storage(read)]
    fn owner() -> State {
        _owner()
    }
}

impl ArcanaVault for Contract {
    #[storage(read, write)]
    fn initialize_vault() {
        initialize_ownership(INITIAL_OWNER);
    }

    #[payable]
    #[storage(read, write)]
    fn deposit(
        request: Request,
        signature: B512,
        from: Address,
        chain_index: u64,
    ) {
        require(
            (request
                    .sources
                    .get(chain_index)
                    .is_some()) && (request
                    .sources
                    .get(chain_index)
                    .unwrap()
                    .chain_id == FUEL_IGNITION_CHAIN_ID),
            VaultError::ChainIdMismatch,
        );

        require(request.expiry > timestamp(), VaultError::RequestExpired);

        require(
            msg_asset_id() == request
                .sources
                .get(chain_index)
                .unwrap()
                .asset_id,
            VaultError::AssetMismatch,
        );
        require(
            msg_amount() == request
                .sources
                .get(chain_index)
                .unwrap()
                .value,
            VaultError::ValueMismatch,
        );

        require(
            !storage::V1
                .deposit_nonce
                .get(request.nonce)
                .try_read()
                .unwrap_or(false),
            VaultError::NonceAlreadyUsed,
        );

        let request_hash = hash_request(request);

        let signed_message_hash = verify_request(signature, from, request_hash);

        storage::V1.deposit_nonce.insert(request.nonce, true);
        storage::V1
            .requests
            .insert(signed_message_hash, request_hash);

        // Can't store a `Request` directly, instead store hash of `Request` and log the `Request` itself along with it's hash.
        log(Deposit {
            from,
            signed_message_hash,
            request_hash,
            request,
        });
    }

    #[storage(read, write)]
    fn fill(request: Request, signature: B512, from: Address) {
        require(
            request
                .destination_chain_id == FUEL_IGNITION_CHAIN_ID,
            VaultError::ChainIdMismatch,
        );

        require(request.expiry > timestamp(), VaultError::RequestExpired);

        require(
            output_count()
                .as_u64() == request
                .destinations
                .len(),
            VaultError::InvalidFillOutputs,
        );
        
        let mut output_index = 0;
        for destination_pair in request.destinations.iter() {
            // Solver MUST include coin outputs that satisfy the destinations. 
            // Methods for variable outputs are unavailable atm so solver must take care to setup the ensure this method doesn't revert 
            // as they may still send the UTXOs.
            // Coin outputs MUST be ordered the same as the destination pairs.
            if destination_pair.value > 0 {
                let output_recipient = output_asset_to(output_index);
                require(
                    (output_recipient
                            .is_some()) && (output_recipient
                            .unwrap() == from),
                    VaultError::InvalidFillOutputs,
                );

                let output_asset_id = output_asset_id(output_index);
                require(
                    (output_asset_id
                            .is_some()) && (output_asset_id
                            .unwrap() == destination_pair
                            .asset_id),
                    VaultError::InvalidFillOutputs,
                );

                let output_amount = output_amount(output_index);
                require(
                    (output_amount
                            .is_some()) && (output_amount
                            .unwrap() == destination_pair
                            .value),
                    VaultError::InvalidFillOutputs,
                );
            }

            output_index = output_index + 1;
        }

        require(
            !storage::V1
                .fill_nonce
                .get(request.nonce)
                .try_read()
                .unwrap_or(false),
            VaultError::NonceAlreadyUsed,
        );

        let request_hash = hash_request(request);

        let signed_message_hash = verify_request(signature, from, request_hash);

        storage::V1.fill_nonce.insert(request.nonce, true);
        storage::V1
            .requests
            .insert(signed_message_hash, request_hash);

        // Can't store a `Request` directly, instead store hash of `Request` and log the `Request` itself along with it's hash.
        log(Fill {
            from,
            signed_message_hash,
            solver: msg_sender().unwrap().as_address().unwrap(),
            request_hash,
            request,
        });
    }

    #[storage(read)]
    fn withdraw(to: Identity, asset_id: AssetId, amount: u64) {
        only_owner();
        reentrancy_guard();

        transfer(to, asset_id, amount);

        log(Withdraw {
            to,
            asset_id,
            amount,
        });
    }

    #[storage(read, write)]
    fn settle(settle_data: SettleData, signature: B512) {
        // Anyone can call this method as it checks if the `settle_data` was signed by the `owner`, 
        // if so the `settle_data` is considered valid.
        reentrancy_guard();

        require(
            settle_data
                .solvers
                .len() == settle_data
                .assets
                .len(),
            VaultError::SolversAndAssetsLengthMismatch,
        );

        require(
            settle_data
                .solvers
                .len() == settle_data
                .amounts
                .len(),
            VaultError::SolversAndAmountsLengthMismatch,
        );

        let settle_data_hash = keccak256((settle_data, FUEL_IGNITION_CHAIN_ID));

        let signed_message_hash = personal_sign_hash(settle_data_hash);

        let recovered_address = ec_recover_address(signature, signed_message_hash).unwrap();

        require(
            State::Initialized(Identity::Address(recovered_address)) == _owner(),
            VaultError::InvalidSignature,
        );

        require(
            !storage::V1
                .settle_nonce
                .get(settle_data.nonce)
                .try_read()
                .unwrap_or(false),
            VaultError::NonceAlreadyUsed,
        );

        storage::V1.settle_nonce.insert(settle_data.nonce, true);

        let mut index = 0;
        while index < settle_data.solvers.len() {
            let solver = settle_data.solvers.get(index).unwrap();
            let asset_id = settle_data.assets.get(index).unwrap();
            let amount = settle_data.amounts.get(index).unwrap();

            transfer(Identity::Address(solver), asset_id, amount);

            log(Settle {
                solver,
                asset_id,
                amount,
                nonce: settle_data.nonce,
            });

            index = index + 1;
        }
    }

    #[storage(read)]
    fn requests(signed_message_hash: b256) -> Option<b256> {
        storage::V1.requests.get(signed_message_hash).try_read()
    }

    #[storage(read)]
    fn deposit_nonce(nonce: u64) -> Option<bool> {
        storage::V1.deposit_nonce.get(nonce).try_read()
    }

    #[storage(read)]
    fn fill_nonce(nonce: u64) -> Option<bool> {
        storage::V1.fill_nonce.get(nonce).try_read()
    }

    #[storage(read)]
    fn settle_nonce(nonce: u64) -> Option<bool> {
        storage::V1.settle_nonce.get(nonce).try_read()
    }
}

fn hash_request(request: Request) -> b256 {
    keccak256(request)
}

fn verify_request(signature: B512, from: Address, request_hash: b256) -> b256 {
    let signed_message_hash = personal_sign_hash(request_hash);

    let recovered_address = ec_recover_address(signature, signed_message_hash).unwrap();

    require(recovered_address == from, VaultError::RequestUnverified);

    signed_message_hash
}
