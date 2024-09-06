// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract Vault is AccessControlUpgradeable {
    using ECDSA for bytes32;

    uint256 public overhead;
    uint256 public vaultBalance;

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
    }

    struct SettleData {
        address[] solvers;
        address[] tokens;
        uint256[] amounts;
    }

    event Deposit(address indexed from, bytes32 indexed requestHash);
    event Fill(address indexed from, bytes32 indexed requestHash, address solver);
    event Rebalance(address token, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize() public initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function _hashRequest(Request calldata request) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                request.sources,
                request.destinationChainID,
                request.destinations,
                request.nonce,
                request.expiry
            )
        );
    }

    function _verify_request(
        bytes calldata signature,
        address from,
        bytes32 structHash
    ) private pure returns (bool, bytes32) {
        // Prepend the Ethereum signed message prefix
        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash)
        );

        // Recover the signer from the signature
        address signer = ethSignedMessageHash.recover(signature);
        return (signer == from, ethSignedMessageHash);
    }

    function deposit(
        Request calldata request,
        bytes calldata signature,
        address from,
        uint256 chain_index
    ) public payable {
        uint256 startGas = gasleft();
        bytes32 structHash = _hashRequest(request);
        (bool success, bytes32 ethSignedMessageHash) = _verify_request(
            signature,
            from,
            structHash
        );
        require(success, "Vault: Invalid signature or from");
        require(
            request.sources[chain_index].chainID == block.chainid,
            "Vault: Chain ID mismatch"
        );
        require(
            depositNonce[request.nonce] == false,
            "Vault: Nonce already used"
        );

        if (request.sources[chain_index].tokenAddress == address(0)) {
            uint256 totalValue = request.sources[chain_index].value;
            require(msg.value == totalValue, "Vault: Value mismatch");
        } else {
            IERC20 token = IERC20(request.sources[chain_index].tokenAddress);
            token.transferFrom(
                from,
                address(this),
                request.sources[chain_index].value
            );
        }

        requests[ethSignedMessageHash] = request;
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
        bytes32 structHash = _hashRequest(request);
        (bool success, bytes32 ethSignedMessageHash) = _verify_request(
            signature,
            from,
            structHash
        );
        require(success, "Vault: Invalid signature or from");
        require(
            request.destinationChainID == block.chainid,
            "Vault: Chain ID mismatch"
        );
        require(
            fillNonce[request.nonce] == false,
            "Vault: Nonce already used"
        );

        requests[ethSignedMessageHash] = request;
        for (uint i = 0; i < request.destinations.length; i++) {
            if (request.destinations[i].tokenAddress == address(0)) {
                require(
                    msg.value == request.destinations[i].value,
                    "Vault: Value mismatch"
                );
                payable(from).transfer(request.destinations[i].value);
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
        emit Fill(from, ethSignedMessageHash, msg.sender);
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
    ) external pure returns (bool, bytes32) {
        return _verify_request(signature, from, _hashRequest(request));
    }

    function setOverHead(
        uint256 _overhead
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        overhead = _overhead;
    }

    function settle(
        SettleData calldata settleData,
        bytes calldata signature
    ) public {
        bytes32 structHash = keccak256(
            abi.encode(
                settleData.solvers,
                settleData.tokens,
                settleData.amounts
            )
        );
        bytes32 signatureHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash)
        );
        address signer = signatureHash.recover(signature);
        require(
            hasRole(DEFAULT_ADMIN_ROLE, signer),
            "Vault: Invalid signature"
        );
        require(
            settleData.solvers.length == settleData.tokens.length &&
                settleData.solvers.length == settleData.amounts.length,
            "Vault: Array length mismatch"
        );

        for (uint i = 0; i < settleData.solvers.length; i++) {
            if (settleData.tokens[i] == address(0)) {
                payable(settleData.solvers[i]).transfer(settleData.amounts[i]);
            } else {
                IERC20 token = IERC20(settleData.tokens[i]);
                token.transfer(settleData.solvers[i], settleData.amounts[i]);
            }
        }
    }

    receive() external payable {
        vaultBalance += msg.value;
    }
}
