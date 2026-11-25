// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Vm} from "forge-std/Vm.sol";
import {Vault} from "../src/Vault.sol";
import {ArbitrumVault} from "../src/ArbitrumVault.sol";

Vm constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

/// @dev `ARBITRUM_VAULT=true` asks for an ArbitrumVault, and code at address 100 marks a Nitro chain. The two
///      must agree, so an unrelated precompile at address 100 stops the deploy instead of the Vault's folds.
function isArbitrumVault() view returns (bool arbitrum) {
    arbitrum = VM.envOr("ARBITRUM_VAULT", false);
    require(arbitrum == (address(100).code.length > 0), "VaultForChain: set ARBITRUM_VAULT exactly on Nitro chains");
}

function vaultContractName() view returns (string memory) {
    return isArbitrumVault() ? "ArbitrumVault.sol:ArbitrumVault" : "Vault.sol:Vault";
}

function vaultCreationCode() view returns (bytes memory) {
    return isArbitrumVault() ? type(ArbitrumVault).creationCode : type(Vault).creationCode;
}

function newVault() returns (Vault) {
    return isArbitrumVault() ? new ArbitrumVault() : new Vault();
}
