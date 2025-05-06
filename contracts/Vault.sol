// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract Vault is Initializable, UUPSUpgradeable, AccessControlUpgradeable, ReentrancyGuardUpgradeable {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    enum Function {
        Deposit,
        Settle
    }

    enum Universe {
        ETHEREUM,
        FUEL,
        SOLANA
    }

    enum RFFState {
        UNPROCESSED,
        DEPOSITED_WITHOUT_GAS_REFUND,
        DEPOSITED_WITH_GAS_REFUND,
        FULFILLED
    }

    mapping(Function => uint256) public overhead;
    uint256 public vaultBalance;
    uint256 public maxGasPrice;

    mapping(bytes32 => RFFState) public requestStates;
    mapping(bytes32 => address) public winningSolver;
    mapping(uint256 => bool) public depositNonce;
    mapping(uint256 => bool) public fillNonce;
    mapping(uint256 => bool) public settleNonce;
    bytes32 private constant REFUND_ACCESS = keccak256("REFUND_ACCESS");
    bytes32 private constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    // Storage gap to reserve slots for future use
    uint256[50] private __gap;

    struct SourcePair {
        Universe universe;
        uint256 chainID;
        bytes32 tokenAddress;
        uint256 value;
    }

    struct DestinationPair {
        bytes32 tokenAddress;
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
        DestinationPair[] destinations;
        uint256 nonce;
        uint256 expiry;
        Party[] parties;
    }

    struct SettleData {
        Universe universe;
        uint256 chainID;
        address[] solvers;
        address[] tokens;
        uint256[] amounts;
        uint256 nonce;
    }

    event Deposit(
        bytes32 indexed requestHash,
        address from,
        bool gasRefunded
    );
    event Fill(
        bytes32 indexed requestHash,
        address from,
        address solver
    );
    event Withdraw(address indexed to, address token, uint256 amount);
    event Settle(address indexed solver, address token, uint256 amount, uint256 indexed nonce);
    event GasPriceUpdate(uint256 gasPrice);
    event GasOverheadUpdate(Function indexed _function, uint256 overhead);
    event ReceiveETH(address indexed from, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) initializer public {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(REFUND_ACCESS, admin);
        _grantRole(UPGRADER_ROLE, admin);

        maxGasPrice = 50 gwei;
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        onlyRole(UPGRADER_ROLE)
        override
    {}

    function _hashRequest(
        Request calldata request
    ) private pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    request.sources,
                    request.destinationUniverse,
                    request.destinationChainID,
                    request.destinations,
                    request.nonce,
                    request.expiry,
                    request.parties
                )
            );
    }
     function bytes32ToAddress(bytes32 a) internal pure returns (address) {
        // Cast the last 20 bytes of bytes32 into an address
        return address(uint160(uint256(a)));
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

    function _deposit(
        Request calldata request,
        bytes calldata signature,
        uint256 chainIndex,
        bool willGasBeRefunded
    ) private {
        address from = extractAddress(request.parties);
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
        require(request.sources[chainIndex].universe == Universe.ETHEREUM, "Vault: Universe mismatch");
        require(!depositNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");

        depositNonce[request.nonce] = true;
        if (willGasBeRefunded) {
            requestStates[ethSignedMessageHash] = RFFState.DEPOSITED_WITH_GAS_REFUND;
        } else {
            requestStates[ethSignedMessageHash] = RFFState.DEPOSITED_WITHOUT_GAS_REFUND;
        }

        if (request.sources[chainIndex].tokenAddress == bytes32(0)) {
            uint256 totalValue = request.sources[chainIndex].value;
            require(msg.value == totalValue, "Vault: Value mismatch");
        } else {
            IERC20 token = IERC20(bytes32ToAddress(request.sources[chainIndex].tokenAddress));
            token.safeTransferFrom(
                from,
                address(this),
                request.sources[chainIndex].value
            );
        }

        emit Deposit(ethSignedMessageHash, from, willGasBeRefunded);
    }

    function deposit(
        Request calldata request,
        bytes calldata signature,
        uint256 chainIndex
    ) external payable nonReentrant {
        _deposit(request, signature, chainIndex, false);
    }

    function extractAddress(Party[] memory parties) internal pure returns (address from) {
          for(uint i = 0; i < parties.length; i++) {
            if (parties[i].universe == Universe.ETHEREUM) {
                 from = bytes32ToAddress(parties[i].address_); 
                 break;
            }
        }
    }

    function depositWithRefund(
        Request calldata request,
        bytes calldata signature,
        uint256 chainIndex
    ) external payable onlyRole(REFUND_ACCESS) nonReentrant {
        uint256 startGas = gasleft();
        _deposit(request, signature, chainIndex, true);
        uint256 gasUsed = startGas - gasleft() + overhead[Function.Deposit];
        uint256 gasPrice = tx.gasprice < maxGasPrice
            ? tx.gasprice
            : maxGasPrice;
        uint256 refund = gasUsed * gasPrice;
        if (refund <= vaultBalance) {
            vaultBalance -= refund;
            (bool sent, ) = msg.sender.call{value: refund}("");
            require(sent, "Vault: Refund failed");
        }
    }

    function fill(
        Request calldata request,
        bytes calldata signature
    ) external payable nonReentrant {
        address from = extractAddress(request.parties);
        bytes32 structHash = _hashRequest(request);
        (bool success, bytes32 ethSignedMessageHash) = _verify_request(
            signature,
            from,
            structHash
        );
        require(success, "Vault: Invalid signature or from");
        require(
            uint256(request.destinationChainID) == block.chainid,
            "Vault: Chain ID mismatch"
        );
        require(request.destinationUniverse == Universe.ETHEREUM, "Vault: Universe mismatch");
        require(!fillNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");

        fillNonce[request.nonce] = true;
        requestStates[ethSignedMessageHash] = RFFState.FULFILLED;
        winningSolver[ethSignedMessageHash] = msg.sender;

        uint256 gasBalance = msg.value;
        emit Fill(ethSignedMessageHash, from, msg.sender);
        for (uint i = 0; i < request.destinations.length; ++i) {
            if (request.destinations[i].tokenAddress == bytes32(0)) {
                require(
                    gasBalance >= request.destinations[i].value,
                    "Vault: Value mismatch"
                );
                require(
                    request.destinations[i].value > 0,
                    "Vault: Value mismatch"
                );
                gasBalance -= request.destinations[i].value;
                (bool sent, ) = payable(from).call{
                    value: request.destinations[i].value
                }("");
                require(sent, "Vault: Transfer failed");
            } else {
                IERC20 token = IERC20(bytes32ToAddress(request.destinations[i].tokenAddress));
                token.safeTransferFrom(
                    msg.sender,
                    from,
                    request.destinations[i].value
                );
            }
        }
    }

    function setMaxGasPrice(
        uint256 _maxGasPrice
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxGasPrice = _maxGasPrice;
        emit GasPriceUpdate(_maxGasPrice);
    }

    function withdraw(
        address to,
        address token,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
        if (token == address(0)) {
            (bool sent, ) = payable(to).call{value: amount}("");
            require(sent, "Vault: Transfer failed");
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
        emit Withdraw(to, token, amount);
    }

    function verifyRequestSignature(
        Request calldata request,
        bytes calldata signature
    ) external pure returns (bool, bytes32) {
        address from = extractAddress(request.parties);
        return _verify_request(signature, from, _hashRequest(request));
    }

    function setOverHead(
        Function _function,
        uint256 _overhead
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        overhead[_function] = _overhead;
        emit GasOverheadUpdate(_function, _overhead);
    }

    function settle(
        SettleData calldata settleData,
        bytes calldata signature
    ) external nonReentrant onlyRole(REFUND_ACCESS) {
        uint256 startGas = gasleft();
        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.solvers,
                settleData.tokens,
                settleData.amounts,
                settleData.nonce
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
            settleData.solvers.length == settleData.tokens.length,
            "Vault: Solvers and tokens array length mismatch"
        );

        require(
            settleData.solvers.length == settleData.amounts.length,
            "Vault: Solvers and amounts array length mismatch"
        );
        require(!settleNonce[settleData.nonce], "Vault: Nonce already used");
        require(settleData.chainID == block.chainid, "Vault: Chain ID mismatch");
        require(settleData.universe == Universe.ETHEREUM, "Vault: Universe mismatch");

        settleNonce[settleData.nonce] = true;
        for (uint i = 0; i < settleData.solvers.length; ++i) {
            emit Settle(
                settleData.solvers[i],
                settleData.tokens[i],
                settleData.amounts[i],
                settleData.nonce
            );
            if (settleData.tokens[i] == address(0)) {
                (bool sent, ) = settleData.solvers[i].call{
                    value: settleData.amounts[i]
                }("");
                require(sent, "Vault: Transfer failed");
            } else {
                IERC20 token = IERC20(settleData.tokens[i]);
                token.safeTransfer(
                    settleData.solvers[i],
                    settleData.amounts[i]
                );
            }
        }
        uint256 gasUsed = startGas - gasleft() + overhead[Function.Settle];
        uint256 gasPrice = tx.gasprice < maxGasPrice
            ? tx.gasprice
            : maxGasPrice;
        uint256 refund = gasUsed * gasPrice;
        if (refund < vaultBalance) {
            vaultBalance -= refund;
            (bool sent, ) = msg.sender.call{value: refund}("");
            require(sent, "Vault: Refund failed");
        }
    }

    receive() external payable {
        vaultBalance = vaultBalance + msg.value;
        emit ReceiveETH(msg.sender, msg.value);
    }
}