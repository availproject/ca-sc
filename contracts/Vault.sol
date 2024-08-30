// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "hardhat/console.sol";

contract Vault is AccessControlUpgradeable, EIP712Upgradeable {
    using ECDSA for bytes32;
    string private constant _REQUEST_TYPE =
        "Request(SourcePair[] sources,uint256 destinationChainID,DestinationPair[] destinations,uint256 nonce,uint256 expiry,uint16 fee)";
    string private constant _SOURCE_PAIR_TYPE =
        "SourcePair(uint256 chainID,address tokenAddress,uint256 value)";
    string private constant _DESTINATION_PAIR_TYPE =
        "DestinationPair(address tokenAddress,uint256 value)";
    uint256 overhead;
    uint256 public vaultBalance;

    // Note: After the main struct defination the rest of the defination should be in alphabetical order
    bytes32 private constant _REQUEST_TYPE_HASH =
        keccak256(
            abi.encodePacked(
                _REQUEST_TYPE,
                _DESTINATION_PAIR_TYPE,
                _SOURCE_PAIR_TYPE
            )
        );
    bytes32 private constant _SOURCE_PAIR_TYPE_HASH =
        keccak256(abi.encodePacked(_SOURCE_PAIR_TYPE));
    bytes32 private constant _DESTINATION_PAIR_TYPE_HASH =
        keccak256(abi.encodePacked(_DESTINATION_PAIR_TYPE));

    mapping(bytes32 => Request) public requests;
    mapping(uint256 => bool) public depositNonce;
    mapping(uint256 => bool) public fillNonce;

    struct SourcePair {
        uint256 chainID;
        address tokenAddress;
        uint256 value;
    }

    struct DestinationPair {
        address tokenAddress;
        uint256 value;
    }

    struct Request {
        SourcePair[] sources;
        uint256 destinationChainID;
        DestinationPair[] destinations;
        uint256 nonce;
        uint256 expiry;
        uint16 fee; // In basis points (i.e 1/100 of a percent)
    }

    event Deposit(address indexed from, bytes32 indexed requestHash);

    event Fill(address indexed from, bytes32 indexed requestHash);

    event Rebalance(address token, uint256 amount);

    // EIP-712 Domain Separator parameters
    string private constant SIGNING_DOMAIN = "ArcanaCredit";
    string private constant SIGNATURE_VERSION = "0.0.1";

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize() public initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        __EIP712_init(SIGNING_DOMAIN, SIGNATURE_VERSION);
    }
    function _hashSourcePairs(
        SourcePair[] calldata sources
    ) private pure returns (bytes32) {
        bytes32[] memory encoded = new bytes32[](sources.length);
        for (uint i = 0; i < sources.length; i++) {
            encoded[i] = keccak256(
                abi.encode(
                    _SOURCE_PAIR_TYPE_HASH,
                    sources[i].chainID,
                    sources[i].tokenAddress,
                    sources[i].value
                )
            );
        }
        return keccak256(abi.encodePacked(encoded));
    }

    function _hashDestinationPairs(
        DestinationPair[] calldata destinations
    ) private pure returns (bytes32) {
        bytes32[] memory encoded = new bytes32[](destinations.length);
        for (uint i = 0; i < destinations.length; i++) {
            encoded[i] = keccak256(
                abi.encode(
                    _DESTINATION_PAIR_TYPE_HASH,
                    destinations[i].tokenAddress,
                    destinations[i].value
                )
            );
        }
        return keccak256(abi.encodePacked(encoded));
    }
    function getStructHash(
        Request calldata request
    ) private view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        _REQUEST_TYPE_HASH,
                        _hashSourcePairs(request.sources),
                        request.destinationChainID,
                        _hashDestinationPairs(request.destinations),
                        request.nonce,
                        request.expiry,
                        request.fee
                    )
                )
            );
    }

    function _verify_request(
        bytes calldata signature,
        address from,
        bytes32 structHash
    ) private pure returns (bool, bytes32) {
        address signer = structHash.recover(signature);
        return (signer == from, structHash);
    }

    function deposit(
        Request calldata request,
        bytes calldata signature,
        address from,
        uint256 chain_index
    ) public payable {
        uint256 startGas = gasleft();
        bytes32 structHash = getStructHash(request);
        (bool success, bytes32 hash) = _verify_request(
            signature,
            from,
            structHash
        );
        require(success, "ArcanaCredit: Invalid signature or from");
        require(
            request.sources[chain_index].chainID == block.chainid,
            "ArcanaCredit: Chain ID mismatch"
        );
        require(
            depositNonce[request.nonce] == false,
            "ArcanaCredit: Nonce already used"
        );

        if (request.sources[chain_index].tokenAddress == address(0)) {
            uint256 totalValue = request.sources[chain_index].value +
                ((request.sources[chain_index].value) * request.fee) /
                10_000;
            require(msg.value == totalValue, "ArcanaCredit: Value mismatch");
        } else {
            IERC20 token = IERC20(request.sources[chain_index].tokenAddress);
            token.transferFrom(
                from,
                address(this),
                request.sources[chain_index].value +
                    ((request.sources[chain_index].value) * request.fee) /
                    10_000
            );
        }

        requests[hash] = request;
        depositNonce[request.nonce] = true;
        emit Deposit(from, structHash);
        uint256 gasUsed = startGas - gasleft() + overhead;
        uint256 refund = gasUsed * tx.gasprice;
        if (refund < vaultBalance) {
            vaultBalance -= refund;
            payable(msg.sender).transfer(refund);
        } else {
            vaultBalance = 0;
        }
    }

    function fill(
        Request calldata request,
        bytes calldata signature,
        address from
    ) public payable {
        bytes32 structHash = getStructHash(request);
        (bool success, bytes32 hash) = _verify_request(
            signature,
            from,
            structHash
        );
        require(success, "ArcanaCredit: Invalid signature or from");
        require(
            request.destinationChainID == block.chainid,
            "ArcanaCredit: Chain ID mismatch"
        );
        require(
            fillNonce[request.nonce] == false,
            "ArcanaCredit: Nonce already used"
        );

        requests[hash] = request;
        for (uint i = 0; i < request.destinations.length; i++) {
            if (request.destinations[i].tokenAddress == address(0)) {
                require(
                    msg.value == request.destinations[i].value,
                    "ArcanaCredit: Value mismatch"
                );
                payable(from).transfer(request.destinations[i].value);
                continue;
            } else {
                IERC20 token = IERC20(request.destinations[i].tokenAddress);
                token.transferFrom(
                    msg.sender,
                    from,
                    request.destinations[i].value
                );
            }
        }
        fillNonce[request.nonce] = true;
        emit Fill(from, structHash);
    }

    function rebalance(
        address token,
        uint256 amount
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20(token).transfer(msg.sender, amount);
        emit Rebalance(token, amount);
    }

    function verifyRequestSignature(
        Request calldata request,
        bytes calldata signature,
        address from
    ) public view returns (bool, bytes32) {
        return _verify_request(signature, from, getStructHash(request));
    }

    function setOverHead(
        uint256 _overhead
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        overhead = _overhead;
    }

    function settle(
        address[] calldata solvers,
        address[] calldata tokens,
        uint256[] calldata amounts
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        require(
            solvers.length == tokens.length && solvers.length == amounts.length,
            "ArcanaCredit: Array length mismatch"
        );
        for (uint i = 0; i < solvers.length; i++) {
            if (tokens[i] == address(0)) {
                payable(solvers[i]).transfer(amounts[i]);
            } else {
                IERC20 token = IERC20(tokens[i]);
                token.transfer(solvers[i], amounts[i]);
            }
        }
    }

    receive() external payable {
        vaultBalance += msg.value;
    }
}
