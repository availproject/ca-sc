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

enum Route {
    NATIVE,
    MAYAN
}

struct SourcePair {
    Universe universe;
    uint256 chainID;
    bytes32 contractAddress;
    uint256 value;
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
    address[] solvers;
    address[] contractAddresses;
    uint256[] amounts;
    uint256 nonce;
}

struct Action {
    SourcePair[] sources;
    Party[] parties;
    bytes32 recipientAddress;
    bytes32 destinationCaip2namespace;
    bytes32 destinationContractAddress;
    uint256 destinationMinTokenAmount;
    uint256 destinationCaip2chainId;
    uint64 nonce;
    uint64 deadline;
}

struct RouterAction {
    bytes32 tokenAddress;
    bytes32 recipientAddress;
    bytes32 destinationCaip2namespace;
    bytes32 destinationContractAddress;
    uint256 destinationMinTokenAmount;
    uint256 amountIn;
    uint256 destinationCaip2chainId;
    uint64 nonce;
    uint64 deadline;
}
