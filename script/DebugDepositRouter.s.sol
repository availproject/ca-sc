// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Vault} from "../src/Vault.sol";
import {Router} from "../src/Router.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Request, SourcePair, DestinationPair, Party, Universe, Route, RFFState} from "../src/types.sol";
import {IRouter} from "../src/interfaces/IRouter.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title DebugDepositRouter
/// @notice Diagnoses why a specific depositRouter call reverted on Base mainnet
contract DebugDepositRouter is Script {
    using ECDSA for bytes32;

    string private constant SIGNATURE_PREFIX = "Sign this intent to proceed \n";

    address constant VAULT_ADDRESS = 0x46efc3e7613b2E079e557868692149080A9f780E;
    address constant SENDER = 0xdA99829d809CeA08301c7ae09931a1AC8Db027F6;

    // From party address (extracted from request.parties)
    address constant FROM_ADDRESS = 0xFD5FF7c848f2ceF79C6B06A6303D593ab8050000;

    // Token: USDC on Base
    address constant TOKEN_ADDRESS = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

    function run() external {
        // Fork Base mainnet (chainID 8453)
        vm.createSelectFork("base");

        console.log("========================================");
        console.log("       DebugDepositRouter Diagnostic      ");
        console.log("========================================");
        console.log("Vault:", VAULT_ADDRESS);
        console.log("Sender:", SENDER);
        console.log("From (signer):", FROM_ADDRESS);
        console.log("Token:", TOKEN_ADDRESS);
        console.log("Block number:", block.number);
        console.log("Block timestamp:", block.timestamp);
        console.log("Chain ID:", block.chainid);
        console.log("");

        // Reconstruct the exact Request struct from the failed call
        Request memory request;

        request.sources = new SourcePair[](1);
        request.sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: 8453,
            contractAddress: bytes32(0x000000000000000000000000833589fCD6eDb6E08f4c7C32D4f71b54bdA02913),
            value: 2247795,
            fee: 2662
        });

        request.destinationUniverse = Universe.ETHEREUM;
        request.destinationChainID = 42161;
        request.recipientAddress = bytes32(0x000000000000000000000000fd5ff7c848f2cef79c6b06a6303d593ab8050000);

        request.destinations = new DestinationPair[](1);
        request.destinations[0] = DestinationPair({
            contractAddress: bytes32(0x000000000000000000000000af88d065e77c8cC2239327C5EDb3A432268e5831), value: 2125068
        });

        request.nonce = 1777379889822;
        request.expiry = 1777382005;

        request.parties = new Party[](1);
        request.parties[0] = Party({
            universe: Universe.ETHEREUM,
            address_: bytes32(0x000000000000000000000000fd5ff7c848f2cef79c6b06a6303d593ab8050000)
        });

        bytes memory signature =
            hex"6cbd0b1de3160ec44caa4ad3deb2cf06398bba325067dc97460e0520ada5fe5711af8c6a18dea4df7dd00c63785a1d501b5c5ca7dce8646c4d8896813293c5cf1c";

        bytes memory routeData =
            hex"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fd5ff7c848f2cef79c6b06a6303d593ab80500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c3ab00000000000000000000000000000000000000000000000000000000000022050000000000000000000000000000000000000000000000000000000069f0b2750000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280b8946d96d25f0026431a241252d227e65c840fbd936cd6cf48b15300f81a3d0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        uint256 chainIndex = 0;
        uint256 destinationChainIndex = 0;
        Route route = Route.MAYAN;

        // Pre-checks
        console.log("--- Pre-Checks ---");

        // 1. Chain ID
        bool chainIdOk = request.sources[chainIndex].chainID == block.chainid;
        console.log("Chain ID match?", chainIdOk);
        if (!chainIdOk) {
            console.log("  Expected:", request.sources[chainIndex].chainID);
            console.log("  Actual (block.chainid):", block.chainid);
        }

        // 2. Expiry
        bool expiryOk = request.expiry > block.timestamp;
        console.log("Request not expired?", expiryOk);
        if (!expiryOk) {
            console.log("  Expiry:", request.expiry);
            console.log("  Block timestamp:", block.timestamp);
            console.log("  Delta (expiry - now):", int256(request.expiry) - int256(block.timestamp));
        }

        // 3. Vault router set?
        Vault vault = Vault(VAULT_ADDRESS);
        address vaultRouter = address(vault.router());
        bool vaultRouterSet = vaultRouter != address(0);
        console.log("Vault router set?", vaultRouterSet);
        console.log("  Vault router address:", vaultRouter);

        // 4. Mayan router set in Router?
        bool mayanRouterSet = false;
        address mayanRouterAddr = address(0);
        if (vaultRouterSet) {
            try IRouter(vaultRouter).routers(route) returns (address r) {
                mayanRouterAddr = r;
                mayanRouterSet = r != address(0);
                console.log("Mayan router set?", mayanRouterSet);
                console.log("  Mayan router address:", r);
            } catch {
                console.log("  ERROR: Could not query routers() on Vault's Router");
            }
        }

        // 5. Nonce used?
        bool nonceUsed = vault.depositNonce(request.nonce);
        console.log("Nonce already used?", nonceUsed);
        if (nonceUsed) {
            console.log("  REVERT REASON: Vault: Nonce already used");
        }

        // 6. Signature verification
        bytes32 requestHash = keccak256(
            abi.encode(
                request.sources,
                request.destinationUniverse,
                request.destinationChainID,
                request.recipientAddress,
                request.destinations,
                request.nonce,
                request.expiry,
                request.parties
            )
        );
        bytes memory msgBytes = abi.encodePacked(SIGNATURE_PREFIX, Strings.toHexString(uint256(requestHash), 32));
        bytes32 signedMessageHash = MessageHashUtils.toEthSignedMessageHash(msgBytes);
        address signer;
        bool sigOk = false;
        try this._recover(signedMessageHash, signature) returns (address _signer) {
            signer = _signer;
            sigOk = signer == FROM_ADDRESS;
            console.log("Signature valid?", sigOk);
            console.log("  Recovered signer:", signer);
            console.log("  Expected signer:", FROM_ADDRESS);
        } catch {
            console.log("  ERROR: Signature recovery failed (malformed sig?)");
        }

        // 7. ERC20 balances / allowance
        IERC20 token = IERC20(TOKEN_ADDRESS);
        uint256 fromBalance = token.balanceOf(FROM_ADDRESS);
        uint256 fromAllowance = token.allowance(FROM_ADDRESS, VAULT_ADDRESS);
        uint256 totalNeeded = request.sources[chainIndex].value + request.sources[chainIndex].fee;
        console.log("Token balance of FROM:", fromBalance);
        console.log("Token allowance (FROM -> Vault):", fromAllowance);
        console.log("Total needed (value + fee):", totalNeeded);
        console.log("Balance sufficient?", fromBalance >= totalNeeded);
        console.log("Allowance sufficient?", fromAllowance >= totalNeeded);

        // 8. Destination index check
        bool destIndexOk = destinationChainIndex < request.destinations.length;
        console.log("Destination index valid?", destIndexOk);

        console.log("");
        console.log("--- Attempting depositRouter call ---");

        // Simulate the exact call as the original sender
        vm.startPrank(SENDER);

        // Encode the call manually to capture revert reason
        bytes memory callData = abi.encodeCall(
            Vault.depositRouter, (request, signature, chainIndex, destinationChainIndex, route, routeData)
        );

        (bool success, bytes memory returnData) = VAULT_ADDRESS.call(callData);

        if (success) {
            console.log("SUCCESS: depositRouter did not revert");
        } else {
            // Decode revert reason
            if (returnData.length >= 4) {
                bytes4 selector = bytes4(returnData);
                string memory reason;
                if (selector == 0x08c379a0) {
                    // Error(string)
                    assembly {
                        returnData := add(returnData, 0x04)
                    }
                    reason = abi.decode(returnData, (string));
                } else {
                    reason = string(
                        abi.encodePacked("Custom error selector: ", Strings.toHexString(uint256(uint32(selector))))
                    );
                }
                console.log("REVERT REASON:", reason);
            } else if (returnData.length > 0) {
                console.log("REVERT DATA (raw):");
                console.logBytes(returnData);
            } else {
                console.log("REVERTED with NO DATA (likely out-of-gas or invalid jump)");
            }
        }

        vm.stopPrank();

        console.log("");
        console.log("========================================");
        console.log("              End Diagnostic            ");
        console.log("========================================");
    }

    // Helper to recover signature (isolates try/catch)
    function _recover(bytes32 hash, bytes memory sig) external pure returns (address) {
        return hash.recover(sig);
    }
}
