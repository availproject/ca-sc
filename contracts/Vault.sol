// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract Vault is AccessControlUpgradeable, ReentrancyGuardUpgradeable {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    uint256 public overhead;
    uint256 public vaultBalance;

    mapping(bytes32 => Request) public requests;
    mapping(uint256 => bool) public depositNonce;
    mapping(uint256 => bool) public fillNonce;
    mapping(uint256 => bool) public settleNonce;

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
        uint256 nonce;
    }

    event Deposit(address indexed from, bytes32 indexed requestHash);
    event Fill(
        address indexed from,
        bytes32 indexed requestHash,
        address solver
    );
    event Rebalance(address token, uint256 amount);
    event Settle(address indexed solver, address token, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize() public initializer {
        __ReentrancyGuard_init();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function _hashRequest(
        Request calldata request
    ) private pure returns (bytes32) {
        return
            keccak256(
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
        uint256 chainIndex
    ) public payable nonReentrant {
        uint256 startGas = gasleft();
        bytes32 structHash = _hashRequest(request);
        (bool success, bytes32 ethSignedMessageHash) = _verify_request(
            signature,
            from,
            structHash
        );
        require(success, "Vault: Invalid signature or from");
        require(
            request.sources[chainIndex].chainID == block.chainid,
            "Vault: Chain ID mismatch"
        );
        require(!depositNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");
        depositNonce[request.nonce] = true;
        requests[ethSignedMessageHash] = request;

        if (request.sources[chainIndex].tokenAddress == address(0)) {
            uint256 totalValue = request.sources[chainIndex].value;
            require(msg.value == totalValue, "Vault: Value mismatch");
        } else {
            IERC20 token = IERC20(request.sources[chainIndex].tokenAddress);
            token.safeTransferFrom(
                from,
                address(this),
                request.sources[chainIndex].value
            );
        }

        emit Deposit(from, ethSignedMessageHash);
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
    ) public payable nonReentrant {
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
        require(!fillNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");
        fillNonce[request.nonce] = true;
        requests[ethSignedMessageHash] = request;
        uint256 gasToken = msg.value;
        emit Fill(from, ethSignedMessageHash, msg.sender);
        for (uint i = 0; i < request.destinations.length; i++) {
            if (request.destinations[i].tokenAddress == address(0)) {
                gasToken -= request.destinations[i].value;
                require(
                    gasToken >= request.destinations[i].value,
                    "Vault: Value mismatch"
                );
                require(
                    request.destinations[i].value > 0,
                    "Vault: Value mismatch"
                );
                payable(from).transfer(request.destinations[i].value);
            } else {
                IERC20 token = IERC20(request.destinations[i].tokenAddress);
                token.safeTransferFrom(
                    msg.sender,
                    from,
                    request.destinations[i].value
                );
            }
        }
    }

    function rebalance(
        address token,
        uint256 amount
    ) public onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        IERC20(token).safeTransfer(msg.sender, amount);
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
    ) public nonReentrant {
        bytes32 structHash = keccak256(
            abi.encode(
                settleData.solvers,
                settleData.tokens,
                settleData.amounts,
                settleData.nonce,
                block.chainid
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
        require(
            settleNonce[settleData.nonce] == false,
            "Vault: Nonce already used"
        );
        settleNonce[settleData.nonce] = true;
        for (uint i = 0; i < settleData.solvers.length; i++) {
            emit Settle(
                settleData.solvers[i],
                settleData.tokens[i],
                settleData.amounts[i]
            );
            if (settleData.tokens[i] == address(0)) {
                payable(settleData.solvers[i]).transfer(settleData.amounts[i]);
            } else {
                IERC20 token = IERC20(settleData.tokens[i]);
                token.safeTransfer(
                    settleData.solvers[i],
                    settleData.amounts[i]
                );
            }
        }
    }

    receive() external payable {
        vaultBalance += msg.value;
    }
}
