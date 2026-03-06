// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

// Imports
import {BaseVaultTest} from "./BaseVaultTest.t.sol";
import {SignatureHelper} from "./helpers/SignatureHelper.sol";
import {Vault} from "../contracts/Vault.sol";

// SignatureHelperTest - Tests for SignatureHelper functionality
// @title SignatureHelperTest
// @notice Tests that SignatureHelper generates valid signatures that Vault can verify
contract SignatureHelperTest is BaseVaultTest {
    // State Variables

    SignatureHelper public sigHelper;

    // Setup

    function setUp() public override {
        super.setUp();
        sigHelper = new SignatureHelper();
    }

    // Tests - Hash Generation

    /// @notice Test that different requests produce different hashes
    function test_HashRequest_DifferentRequests() public view {
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = Vault.SourcePair({
            universe: Vault.Universe.ETHEREUM,
            chainID: 1,
            contractAddress: bytes32(uint256(uint160(address(1)))),
            value: 100 ether,
            fee: 0
        });

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = Vault.DestinationPair({
            contractAddress: bytes32(uint256(uint160(address(2)))),
            value: 100 ether
        });

        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = Vault.Party({
            universe: Vault.Universe.ETHEREUM,
            address_: bytes32(uint256(uint160(address(3))))
        });

        Vault.Request memory request1 = Vault.Request({
            sources: sources,
            destinationUniverse: Vault.Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(address(4)))),
            destinations: destinations,
            nonce: 1,
            expiry: 1234567890,
            parties: parties
        });

        // Change nonce
        Vault.Request memory request2 = Vault.Request({
            sources: sources,
            destinationUniverse: Vault.Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(address(4)))),
            destinations: destinations,
            nonce: 2, // Different nonce
            expiry: 1234567890,
            parties: parties
        });

        bytes32 hash1 = sigHelper.hashRequest(request1);
        bytes32 hash2 = sigHelper.hashRequest(request2);
        assertTrue(hash1 != hash2, "Different requests should have different hashes");
    }

    // Tests - EIP-191 Message Creation

    /// @notice Test that EIP-191 message has correct format
    function test_CreateEip191Message_Format() public view {
        bytes32 requestHash = keccak256("test");
        bytes memory message = sigHelper.createEip191Message(requestHash);

        // Message should contain the prefix
        string memory messageStr = string(message);
        assertTrue(
            contains(messageStr, "Sign this intent to proceed"),
            "Message should contain prefix"
        );

        // Message should contain 0x prefix for hex
        assertTrue(contains(messageStr, "0x"), "Message should contain 0x prefix");

        // Message length should be 95 bytes (29 prefix + 66 hex)
        assertEq(message.length, 95, "Message length should be 95 bytes");
    }


    // Helper Functions

    /// @notice Check if a string contains a substring
    function contains(string memory str, string memory substr) internal pure returns (bool) {
        bytes memory strBytes = bytes(str);
        bytes memory substrBytes = bytes(substr);

        if (substrBytes.length > strBytes.length) {
            return false;
        }

        for (uint256 i = 0; i <= strBytes.length - substrBytes.length; i++) {
            bool match_ = true;
            for (uint256 j = 0; j < substrBytes.length; j++) {
                if (strBytes[i + j] != substrBytes[j]) {
                    match_ = false;
                    break;
                }
            }
            if (match_) {
                return true;
            }
        }
        return false;
    }
}
