// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Vault} from "../src/Vault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Request, SourcePair, DestinationPair, Party, Universe} from "../src/types.sol";

contract TestVaultNativeEthOnBaseFork is Script {
    uint256 constant FORK_BLOCK_NUMBER = 20_000_000;

    function run() external {
        // Fork Base network
        uint256 forkId = vm.createFork(
            vm.rpcUrl("base"),
            FORK_BLOCK_NUMBER
        );
        vm.selectFork(forkId);

        console.log("Forked Base at block:", FORK_BLOCK_NUMBER);
        console.log("Current chain ID:", block.chainid);

        // Set up test accounts
        uint256 adminPk = 0x1;
        uint256 userPk = 0x2;

        address admin = vm.addr(adminPk);
        address user = vm.addr(userPk);

        console.log("\nAdmin address:", admin);
        console.log("User address:", user);

        // Give admin some ETH for deployment
        vm.deal(admin, 10 ether);
        console.log("Gave admin 10 ETH for deployment");

        // Deploy Vault implementation and proxy
        vm.startBroadcast(adminPk);

        Vault vaultImpl = new Vault();
        console.log("Vault implementation deployed at:", address(vaultImpl));

        bytes memory initData = abi.encodeCall(Vault.initialize, (admin));
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), initData);
        Vault vault = Vault(payable(address(vaultProxy)));

        console.log("Vault proxy deployed at:", address(vault));

        vm.stopBroadcast();

        // Give user ETH for deposit
        uint256 depositAmount = 5 ether;
        vm.deal(user, depositAmount);
        console.log("\nGave user", depositAmount / 1e18, "ETH for deposit");
        console.log("User ETH balance:", user.balance / 1e18, "ETH");

        // Create a native ETH deposit request
        uint256 nonce = 1;
        uint256 expiry = block.timestamp + 1 hours;

        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(0), // Native ETH
            value: depositAmount
        });

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({
            contractAddress: bytes32(0), // Native ETH destination
            value: depositAmount
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({
            universe: Universe.ETHEREUM,
            address_: bytes32(uint256(uint160(user)))
        });

        Request memory request = Request({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: block.chainid,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: nonce,
            expiry: expiry,
            parties: parties
        });

        // Sign the request
        bytes32 requestHash = keccak256(abi.encode(
            sources,
            Universe.ETHEREUM,
            block.chainid,
            bytes32(uint256(uint160(user))),
            destinations,
            nonce,
            expiry,
            parties
        ));

        bytes32 ethSignedHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            requestHash
        ));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, ethSignedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Check balances before deposit
        uint256 userBalanceBefore = user.balance;
        uint256 vaultBalanceBefore = address(vault).balance;

        console.log("\n=== Before Deposit ===");
        console.log("User ETH balance:", userBalanceBefore / 1e18, "ETH");
        console.log("Vault ETH balance:", vaultBalanceBefore / 1e18, "ETH");

        // Perform deposit
        vm.prank(user);
        vault.deposit{value: depositAmount}(request, signature, 0);

        // Check balances after deposit
        uint256 userBalanceAfter = user.balance;
        uint256 vaultBalanceAfter = address(vault).balance;

        console.log("\n=== After Deposit ===");
        console.log("User ETH balance:", userBalanceAfter / 1e18, "ETH");
        console.log("Vault ETH balance:", vaultBalanceAfter / 1e18, "ETH");
        console.log("Deposit amount:", depositAmount / 1e18, "ETH");

        // Verify the deposit
        require(userBalanceAfter == userBalanceBefore - depositAmount, "User balance incorrect");
        require(vaultBalanceAfter == vaultBalanceBefore + depositAmount, "Vault balance incorrect");

        console.log("\n✅ Native ETH deposit test passed!");
    }
}
