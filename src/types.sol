// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

enum Universe {
    ETHEREUM,
    FUEL,
    SOLANA,
    TRON
}

enum RFFState {
    UNPROCESSED,
    DEPOSITED,
    FULFILLED
}

struct SourcePair {
    Universe universe;
    uint256 chainID;
    bytes32 contractAddress;
    uint256 value;
    uint256 fee;
}

struct DestinationPair {
    bytes32 contractAddress;
    uint256 value;
}

struct Party {
    Universe universe;
    bytes32 address_; // address is a reserved keyword
}

struct Request {
    SourcePair[] sources;
    Universe destinationUniverse;
    uint256 destinationChainID;
    bytes32 recipientAddress;
    DestinationPair[] destinations;
    uint256 nonce;
    uint256 expiry;
    Party[] parties;
}

struct SettleData {
    Universe universe;
    uint256 chainID;
    address vaultAddress;
    address[] solvers;
    address[] contractAddresses;
    uint256[] amounts;
    uint256 nonce;
}

/// @notice Source entry of an External RFF request. Identical to SourcePair with a trailing
/// payload commitment. Field order is part of the signed ABI and MUST NOT change within v1.
struct ExternalSourcePair {
    Universe universe;
    uint256 chainID;
    bytes32 contractAddress;
    uint256 value;
    uint256 fee;
    bytes32 payloadHash;
}

/// @notice External RFF request signed by the user. Field order is part of the signed ABI and
/// MUST NOT change within v1.
struct ExternalRequest {
    ExternalSourcePair[] sources;
    Universe destinationUniverse;
    uint256 destinationChainID;
    bytes32 recipientAddress;
    DestinationPair[] destinations;
    uint256 nonce;
    uint256 expiry;
    Party[] parties;
    bytes arbitaryData;
}

/// @notice Generic routing payload executed by the external intent Executor. Field order is part
/// of the payload ABI and MUST NOT change within v1.
struct RoutingPayload {
    string protocolTag;
    address target;
    bytes callData;
    bytes arbitary_data;
}
