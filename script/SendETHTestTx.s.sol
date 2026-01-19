// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Vault} from "../src/Vault.sol";
import {Action, SourcePair, Party, Universe, Route} from "../src/types.sol";

/// @title SendETHTestTx
/// @notice Replicates test_VaultDepositRouter_ETH logic for live network
contract SendETHTestTx is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address vaultAddress = vm.envAddress("VAULT_PROXY_ADDRESS");
        
        // Configuration
        uint256 amount = 0.000001 ether; 
        uint256 currentChainId = block.chainid;
        
        console.log("Deployer:", deployer);
        console.log("Vault:", vaultAddress);
        console.log("Amount (ETH):", amount);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Prepare Data
        bytes memory routeData = abi.encode(
            uint64(0), // gasDrop
            uint64(0)  // deadline
        );

        // 2. Create Action
        Action memory action;
        
        // Source: Native ETH
        action.sources = new SourcePair[](1);
        action.sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: currentChainId,
            contractAddress: bytes32(0), // 0x0 for Native ETH
            value: amount
        });

        // Parties
        action.parties = new Party[](1);
        action.parties[0] = Party({
            universe: Universe.ETHEREUM,
            address_: bytes32(uint256(uint160(deployer)))
        });

        // Rest of Action
        action.recipientAddress = bytes32(uint256(uint160(deployer))); // Send to self
        action.destinationCaip2namespace = keccak256("eip155");
        action.destinationContractAddress = bytes32(0); // Native ETH on dest
        action.destinationCaip2ChainId = 1; // Ethereum Mainnet (supported in MayanRouter)
        action.destinationMinTokenAmount = (amount * 90) / 100; // 90% slippage
        action.nonce = uint128(block.timestamp); 
        action.expiry = uint128(block.timestamp + 1 hours);

        // 3. Sign Action
        bytes32 actionHash = keccak256(abi.encode(action));
        bytes32 signedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", actionHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, signedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // 4. Execute depositRouter
        console.log("Executing depositRouter...");
        
        (bool success, ) = vaultAddress.call{value: amount}(
            abi.encodeCall(
                Vault.depositRouter,
                (action, signature, 0, Route.MAYAN, routeData)
            )
        );

        if (success) {
            console.log("Transaction SUCCESS");
        } else {
            console.log("Transaction REVERTED locally (check Tenderly)");
        }

        vm.stopBroadcast();
    }
}