// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract Vault is AccessControlUpgradeable, ReentrancyGuardUpgradeable {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    enum Function {
        Deposit,
        Settle
    }

    enum Universe {
        EVM,
        FUEL,
        SOLANA
    }

    mapping(Function => uint256) public overhead;
    uint256 public vaultBalance;
    uint256 public maxGasPrice;

    mapping(bytes32 => Request) public requests;
    mapping(uint256 => bool) public depositNonce;
    mapping(uint256 => bool) public fillNonce;
    mapping(uint256 => bool) public settleNonce;
    bytes32 private constant REFUND_ACCESS = keccak256("REFUND_ACCESS");

    // Storage gap to reserve slots for future use
    uint256[50] private __gap;

    struct SourcePair {
        bytes32 chainID;
        bytes32 tokenAddress;
        uint256 value;
    }

    struct DestinationPair {
        bytes32 tokenAddress;
        uint256 value;
    }

    struct Request {
        SourcePair[] sources;
        bytes32 destinationChainID;
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

    event Deposit(address indexed from, bytes32 indexed requestHash, bool gasRefunded);
    event Fill(
        address indexed from,
        bytes32 indexed requestHash,
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

    function initialize() public initializer {
        __ReentrancyGuard_init();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(REFUND_ACCESS, msg.sender);
        maxGasPrice = 50 gwei;
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
        address from,
        uint256 chainIndex,
        bool gasRefunded
    ) private {
        bytes32 structHash = _hashRequest(request);
        (bool success, bytes32 ethSignedMessageHash) = _verify_request(
            signature,
            from,
            structHash
        );
        require(success, "Vault: Invalid signature or from");
        require(
            uint256(request.sources[chainIndex].chainID) == block.chainid,
            "Vault: Chain ID mismatch"
        );
        require(!depositNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");
        depositNonce[request.nonce] = true;
        requests[ethSignedMessageHash] = request;

        if ( request.sources[chainIndex].tokenAddress == bytes32(0) ) {
            uint256 totalValue = request.sources[chainIndex].value;
            require(msg.value == totalValue, "Vault: Value mismatch");
        } else {
            IERC20 token = IERC20( bytes32ToAddress (request.sources[chainIndex].tokenAddress ) );
            uint256 balanceBefore = token.balanceOf(address(this));
            token.safeTransferFrom(
                from,
                address(this),
                request.sources[chainIndex].value
            );
            require(
                token.balanceOf(address(this)) - balanceBefore ==
                    request.sources[chainIndex].value,
                "Vault: Transfer failed"
            );
        }

        emit Deposit(from, ethSignedMessageHash, gasRefunded);
    }

    function deposit(
        Request calldata request,
        bytes calldata signature,
        address from,
        uint256 chainIndex
    ) public payable nonReentrant {
        _deposit(request, signature, from, chainIndex, false);
    }

    function depositWithRefund(
        Request calldata request,
        bytes calldata signature,
        address from,
        uint256 chainIndex
    ) public payable onlyRole(REFUND_ACCESS) nonReentrant {
        uint256 startGas = gasleft();
        _deposit(request, signature, from, chainIndex, true);
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
            uint256(request.destinationChainID) == block.chainid,
            "Vault: Chain ID mismatch"
        );
        require(!fillNonce[request.nonce], "Vault: Nonce already used");
        require(request.expiry > block.timestamp, "Vault: Request expired");
        fillNonce[request.nonce] = true;
        requests[ethSignedMessageHash] = request;
        uint256 gasToken = msg.value;
        emit Fill(from, ethSignedMessageHash, msg.sender);
        for (uint i = 0; i < request.destinations.length; ++i) {
            if (request.destinations[i].tokenAddress == bytes32(0)) {
                require(
                    gasToken >= request.destinations[i].value,
                    "Vault: Value mismatch"
                );
                require(
                    request.destinations[i].value > 0,
                    "Vault: Value mismatch"
                );
                gasToken -= request.destinations[i].value;
                (bool sent, ) = payable(from).call{
                    value: request.destinations[i].value
                }("");
                require(sent, "Vault: Transfer failed");
            } else {
                IERC20 token = IERC20( bytes32ToAddress(request.destinations[i].tokenAddress));
                uint256 balanceBefore = token.balanceOf(from);
                token.safeTransferFrom(
                    msg.sender,
                    from,
                    request.destinations[i].value
                );
                require(
                    token.balanceOf(from) - balanceBefore ==
                        request.destinations[i].value,
                    "Vault: Transfer failed"
                );
            }
        }
    }

    function setMaxGasPrice(
        uint256 _maxGasPrice
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        maxGasPrice = _maxGasPrice;
        emit GasPriceUpdate(_maxGasPrice);
    }

    function withdraw(
        address to,
        address token,
        uint256 amount
    ) public onlyRole(DEFAULT_ADMIN_ROLE) nonReentrant {
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
        bytes calldata signature,
        address from
    ) external pure returns (bool, bytes32) {
        return _verify_request(signature, from, _hashRequest(request));
    }

    function setOverHead(
        Function _function,
        uint256 _overhead
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        overhead[_function] = _overhead;
        emit GasOverheadUpdate(_function, _overhead);
    }

    function settle(
        SettleData calldata settleData,
        bytes calldata signature
    ) public nonReentrant onlyRole(REFUND_ACCESS) {
        uint256 startGas = gasleft();
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
            settleData.solvers.length == settleData.tokens.length,
            "Vault: Solvers and tokens array length mismatch"
        );

        require(
            settleData.solvers.length == settleData.amounts.length,
            "Vault: Solvers and amounts array length mismatch"
        );
        require(!settleNonce[settleData.nonce], "Vault: Nonce already used");
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
