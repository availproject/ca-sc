// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Vault} from "../src/Vault.sol";
import {Request, SourcePair, DestinationPair, Party, Universe, Route} from "../src/types.sol";

/// @title SendETHTestTx
/// @notice Replicates test_VaultDepositRouter_ETH logic for live network
contract SendETHTestTx is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address vaultAddress = vm.envAddress("VAULT_PROXY_ADDRESS");

        // Configuration
        uint256 amount = 0.000_001 ether;
        uint256 currentChainId = block.chainid;

        console.log("Deployer:", deployer);
        console.log("Vault:", vaultAddress);
        console.log("Amount (ETH):", amount);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Prepare Data
        bytes memory routeData = abi.encode(
            uint64(0), // gasDrop
            bytes32(uint256(uint160(deployer))), // destAddr
            bytes32(0), // referrerAddr
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0), // random
            uint8(0) // payloadType
        );

        // 2. Create Request
        Request memory request;

        // Sources: Native ETH
        request.sources = new SourcePair[](1);
        request.sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: currentChainId,
            contractAddress: bytes32(0), // 0x0 for Native ETH
            value: amount,
            fee: 0
        });

        // Destinations
        request.destinations = new DestinationPair[](1);
        request.destinations[0] = DestinationPair({
            contractAddress: bytes32(0), // Native ETH on dest
            value: (amount * 90) / 100 // 90% slippage
        });

        // Parties
        request.parties = new Party[](1);
        request.parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(deployer)))});

        // Rest of Request
        request.recipientAddress = bytes32(uint256(uint160(deployer))); // Send to self
        request.destinationUniverse = Universe.ETHEREUM; // eip155 equivalent
        request.destinationChainID = 1; // Ethereum Mainnet (supported in MayanRouter)
        request.nonce = uint64(block.timestamp);
        request.expiry = uint64(block.timestamp + 1 hours);

        // 3. Sign Request
        bytes32 requestHash = keccak256(abi.encode(request));
        bytes32 signedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", requestHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, signedMessageHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // 4. Execute depositRouter
        console.log("Executing depositRouter...");

        (bool success,) = vaultAddress.call{value: amount}(
            abi.encodeCall(Vault.depositRouter, (request, signature, 0, 0, Route.MAYAN, routeData))
        );

        if (success) {
            console.log("Transaction SUCCESS");
        } else {
            console.log("Transaction REVERTED locally (check Tenderly)");
        }

        vm.stopBroadcast();
    }
}
