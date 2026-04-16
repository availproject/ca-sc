// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

// Imports
import {Test} from "forge-std/Test.sol";
import {Vault} from "../../contracts/Vault.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

// SignatureHelper - Contract for off-chain signature generation and verification
// @title SignatureHelper
// @notice Contract providing helper functions for EIP-191 signature generation
// @dev This contract MUST match Vault.sol encoding exactly for signatures to verify correctly.
//      Used in tests to generate valid signatures that the Vault contract can verify.
//
//      Encoding format:
//      1. Request hash: keccak256(abi.encode(sources, destinationUniverse, destinationChainID,
//         recipientAddress, destinations, nonce, expiry, parties))
//      2. Message: "Sign this intent to proceed \n" + hexString(hash) [0x + 64 chars]
//      3. EIP-191 hash: keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
//
// @dev Inherits from Test to access vm cheatcodes for signing
contract SignatureHelper is Test {
    // Constants

    /// @notice Prefix added to signatures - MUST match Vault.SIGNATURE_PREFIX exactly
    /// @dev The space before \n is intentional and required for signature compatibility
    string private constant SIGNATURE_PREFIX = "Sign this intent to proceed \n";

    // Hash Functions

    /**
     * @dev Hashes a Request struct exactly like Vault._hashRequest
     * @param request The Request struct to hash
     * @return bytes32 The keccak256 hash of all request fields
     *
     * Encoding format (MUST match Vault.sol exactly):
     * keccak256(abi.encode(
     *     request.sources,
     *     request.destinationUniverse,
     *     request.destinationChainID,
     *     request.recipientAddress,
     *     request.destinations,
     *     request.nonce,
     *     request.expiry,
     *     request.parties
     * ))
     */
    function hashRequest(Vault.Request memory request) public pure returns (bytes32) {
        return keccak256(
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
    }

    // EIP-191 Message Functions

    /**
     * @dev Creates the EIP-191 message with custom prefix
     * @param requestHash The hash of the request (from hashRequest)
     * @return bytes The formatted message bytes
     *
     * Format: SIGNATURE_PREFIX + hexString(requestHash)
     * Example: "Sign this intent to proceed \n0x1234...abcd"
     *          (prefix = 29 bytes, hex = 66 bytes [0x + 64 chars], total = 95 bytes)
     */
    function createEip191Message(bytes32 requestHash) public pure returns (bytes memory) {
        return abi.encodePacked(
            SIGNATURE_PREFIX,
            Strings.toHexString(uint256(requestHash), 32) // 0x + 64 hex chars = 66 bytes
        );
    }

    /**
     * @dev Creates the Ethereum signed message hash (EIP-191)
     * @param message The message bytes to hash
     * @return bytes32 The Ethereum signed message hash
     *
     * EIP-191 format: keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
     * Example: "\x19Ethereum Signed Message:\n95" + message (where 95 is the message length)
     */
    function toEthSignedMessageHash(bytes memory message) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(message.length), message));
    }

    /**
     * @dev Convenience function to get the EIP-191 hash directly from a request hash
     * @param requestHash The hash of the request
     * @return bytes32 The Ethereum signed message hash
     */
    function getEip191Hash(bytes32 requestHash) public pure returns (bytes32) {
        bytes memory message = createEip191Message(requestHash);
        return toEthSignedMessageHash(message);
    }

    // Signature Functions

    /**
     * @dev Signs a request using a private key (Foundry cheatcode)
     * @param request The request to sign
     * @param privateKey The private key to sign with (Foundry vm.sign cheatcode)
     * @return bytes The signature bytes (r, s, v) packed
     *
     * Uses vm.sign() cheatcode which returns (v, r, s) and packs them as:
     * - r: bytes32 (first 32 bytes)
     * - s: bytes32 (next 32 bytes)
     * - v: uint8 (last 1 byte)
     * Total: 65 bytes
     */
    function signRequest(Vault.Request memory request, uint256 privateKey) public pure returns (bytes memory) {
        bytes32 requestHash = hashRequest(request);
        bytes memory message = createEip191Message(requestHash);
        bytes32 ethHash = toEthSignedMessageHash(message);

        // vm.sign returns (uint8 v, bytes32 r, bytes32 s)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethHash);

        // Pack as (r, s, v) - 65 bytes total
        return abi.encodePacked(r, s, v);
    }

    /**
     * @dev Signs a raw hash directly using a private key
     * @param requestHash The request hash to sign (skips hashRequest step)
     * @param privateKey The private key to sign with
     * @return bytes The signature bytes (r, s, v) packed
     */
    function signHash(bytes32 requestHash, uint256 privateKey) public pure returns (bytes memory) {
        bytes memory message = createEip191Message(requestHash);
        bytes32 ethHash = toEthSignedMessageHash(message);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethHash);
        return abi.encodePacked(r, s, v);
    }

    // Verification Functions

    /**
     * @dev Recovers the signer address from a signature
     * @param ethHash The Ethereum signed message hash
     * @param signature The signature bytes (r, s, v)
     * @return address The address that signed the message
     */
    function recoverSigner(bytes32 ethHash, bytes memory signature) public pure returns (address) {
        return ECDSA.recover(ethHash, signature);
    }

    /**
     * @dev Verifies that a signature is valid for a given request and expected signer
     * @param request The request that was signed
     * @param signature The signature bytes
     * @param expectedSigner The expected address of the signer
     * @return bool True if the signature is valid and matches the expected signer
     */
    function verifyRequest(Vault.Request memory request, bytes memory signature, address expectedSigner)
        public
        pure
        returns (bool)
    {
        bytes32 requestHash = hashRequest(request);
        bytes memory message = createEip191Message(requestHash);
        bytes32 ethHash = toEthSignedMessageHash(message);

        address signer = recoverSigner(ethHash, signature);
        return signer == expectedSigner;
    }

    /**
     * @dev Verifies that a signature is valid for a given request hash and expected signer
     * @param requestHash The hash of the request
     * @param signature The signature bytes
     * @param expectedSigner The expected address of the signer
     * @return bool True if the signature is valid and matches the expected signer
     */
    function verifyHash(bytes32 requestHash, bytes memory signature, address expectedSigner)
        public
        pure
        returns (bool)
    {
        bytes memory message = createEip191Message(requestHash);
        bytes32 ethHash = toEthSignedMessageHash(message);

        address signer = recoverSigner(ethHash, signature);
        return signer == expectedSigner;
    }

    // Utility Functions

    /**
     * @dev Gets the expected message length for a given request hash
     * @param requestHash The hash of the request
     * @return uint256 The length of the formatted message
     *
     * Length calculation:
     * - SIGNATURE_PREFIX: 29 bytes ("Sign this intent to proceed \n")
     * - hex string: 66 bytes ("0x" + 64 hex chars)
     * - Total: 95 bytes
     */
    function getMessageLength(bytes32 requestHash) public pure returns (uint256) {
        bytes memory message = createEip191Message(requestHash);
        return message.length;
    }

    /**
     * @dev Returns the raw message bytes for debugging/inspection
     * @param requestHash The hash of the request
     * @return string The message as a string (prefix + hex)
     */
    function getMessageString(bytes32 requestHash) public pure returns (string memory) {
        bytes memory message = createEip191Message(requestHash);
        return string(message);
    }
}
