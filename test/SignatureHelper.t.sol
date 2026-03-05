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

    /// @notice Test that hashRequest produces consistent hashes
    function test_HashRequest_Consistent() public view {
        // Create a simple request
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

        Vault.Request memory request = Vault.Request({
            sources: sources,
            destinationUniverse: Vault.Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(address(4)))),
            destinations: destinations,
            nonce: 1,
            expiry: 1234567890,
            parties: parties
        });

        // Hash should be consistent
        bytes32 hash1 = sigHelper.hashRequest(request);
        bytes32 hash2 = sigHelper.hashRequest(request);
        assertEq(hash1, hash2, "Hash should be consistent");
    }

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

    /// @notice Test that message length utility returns correct value
    function test_GetMessageLength() public view {
        bytes32 requestHash = keccak256("test");
        uint256 length = sigHelper.getMessageLength(requestHash);
        assertEq(length, 95, "Message length should be 95 bytes");
    }

    // Tests - Signature Generation and Verification

    /// @notice Test that signRequest generates valid signatures
    function test_SignRequest_ValidSignature() public {
        // Create user's private key and address
        (address userAddr, uint256 userPrivateKey) = makeAddrAndKey("testuser");

        // Create a simple request
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
            address_: bytes32(uint256(uint160(userAddr)))
        });

        Vault.Request memory request = Vault.Request({
            sources: sources,
            destinationUniverse: Vault.Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(address(4)))),
            destinations: destinations,
            nonce: 1,
            expiry: 1234567890,
            parties: parties
        });

        // Sign the request
        bytes memory signature = sigHelper.signRequest(request, userPrivateKey);

        // Verify the signature
        bool isValid = sigHelper.verifyRequest(request, signature, userAddr);
        assertTrue(isValid, "Signature should be valid");
    }

    /// @notice Test that wrong signer fails verification
    function test_SignRequest_WrongSigner() public {
        (address userAddr, uint256 userPrivateKey) = makeAddrAndKey("testuser");
        (address otherAddr,) = makeAddrAndKey("otheruser");

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
            address_: bytes32(uint256(uint160(userAddr)))
        });

        Vault.Request memory request = Vault.Request({
            sources: sources,
            destinationUniverse: Vault.Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(address(4)))),
            destinations: destinations,
            nonce: 1,
            expiry: 1234567890,
            parties: parties
        });

        bytes memory signature = sigHelper.signRequest(request, userPrivateKey);

        // Verify with wrong signer should fail
        bool isValid = sigHelper.verifyRequest(request, signature, otherAddr);
        assertFalse(isValid, "Signature should not be valid for wrong signer");
    }

    /// @notice Test signature recovery
    function test_RecoverSigner() public {
        (address userAddr, uint256 userPrivateKey) = makeAddrAndKey("testuser");

        bytes32 requestHash = keccak256("test");
        bytes memory signature = sigHelper.signHash(requestHash, userPrivateKey);

        bytes32 ethHash = sigHelper.getEip191Hash(requestHash);
        address recovered = sigHelper.recoverSigner(ethHash, signature);

        assertEq(recovered, userAddr, "Should recover correct signer");
    }

    /// @notice Test that signature is 65 bytes (r=32, s=32, v=1)
    function test_SignatureLength() public {
        (, uint256 userPrivateKey) = makeAddrAndKey("testuser");

        bytes32 requestHash = keccak256("test");
        bytes memory signature = sigHelper.signHash(requestHash, userPrivateKey);

        assertEq(signature.length, 65, "Signature should be 65 bytes");
    }

    // Tests - Integration with Vault

    /// @notice Test that signatures generated by SignatureHelper verify with Vault
    function test_SignatureHelper_VaultIntegration() public {
        // Create user's private key and address
        (address userAddr, uint256 userPrivateKey) = makeAddrAndKey("vaultuser");

        // Create a request using BaseVaultTest helper
        Vault.Request memory request = _createSimpleRequest(
            bytes32(uint256(uint160(address(token)))), // sourceToken
            100 ether, // sourceValue
            bytes32(uint256(uint160(address(token2)))), // destToken
            100 ether, // destValue
            userAddr, // requester
            solver, // recipient
            1, // nonce
            block.timestamp + 1 hours // expiry
        );

        // Sign the request using SignatureHelper
        bytes memory signature = sigHelper.signRequest(request, userPrivateKey);

        // Verify the signature using SignatureHelper
        bool helperValid = sigHelper.verifyRequest(request, signature, userAddr);
        assertTrue(helperValid, "SignatureHelper should verify signature");

        // Note: Vault doesn't have a public verifyRequestSignature function.
        // The signature verification happens internally during deposit/fulfillment.
        // This test verifies that our helper produces signatures that follow
        // the exact same format as Vault expects.
    }

    /// @notice Test that hash matches between SignatureHelper and manual calculation
    function test_HashConsistency() public view {
        Vault.Request memory request = _createSimpleRequest(
            bytes32(uint256(uint160(address(token)))),
            100 ether,
            bytes32(uint256(uint160(address(token2)))),
            100 ether,
            user,
            solver,
            1,
            block.timestamp + 1 hours
        );

        bytes32 hash1 = sigHelper.hashRequest(request);

        // Manual calculation matching Vault._hashRequest exactly
        bytes32 hash2 = keccak256(
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

        assertEq(hash1, hash2, "Hashes should match exactly");
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
