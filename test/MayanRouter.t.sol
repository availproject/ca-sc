// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {Router} from "../src/Router.sol";
import {Vault} from "../src/Vault.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {Action, SourcePair, Party, Universe, Route} from "../src/types.sol";
import {console} from "forge-std/console.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

interface IMayanForwarder {
    struct PermitParams {
        uint256 value;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    function forwardERC20(
        address tokenIn,
        uint256 amountIn,
        PermitParams calldata permitParams,
        address mayanProtocol,
        bytes calldata protocolData
    ) external payable;

    function forwardEth(
        address mayanProtocol,
        bytes calldata protocolData
    ) external payable;
}

interface IMayanSwiftV2 {
    struct OrderParams {
        uint8 payloadType;
        bytes32 trader;
        bytes32 destAddr;
        uint16 destChainId;
        bytes32 referrerAddr;
        bytes32 tokenOut;
        uint64 minAmountOut;
        uint64 gasDrop;
        uint64 cancelFee;
        uint64 refundFee;
        uint64 deadline;
        uint8 referrerBps;
        uint8 auctionMode;
        bytes32 random;
    }

    function createOrderWithToken(
        address tokenIn,
        uint256 amountIn,
        OrderParams memory params,
        bytes memory customPayload
    ) external returns (bytes32 orderHash);
}

contract MayanRouterTest is Test {
    MayanRouter public mayanRouter;
    Router public router;
    Vault public vault;
    MockERC20 public token;

    address public admin;
    address public user;
    uint256 public userPrivateKey;
    address public recipient;

    // Mayan Protocol addresses on Base
    address constant MAYAN_FORWARDER =
        0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;
    // Swift V2 protocol address on Base
    address constant SWIFT_V2_BASE = 0xc05fb021704D4709c8C058da691fdf4070574685;

    function setUp() public {
        admin = makeAddr("admin");
        userPrivateKey = 0xA11CE;
        user = vm.addr(userPrivateKey);
        recipient = makeAddr("recipient");

        // Deploy MayanRouter
        mayanRouter = new MayanRouter();

        // Deploy Router implementation and proxy
        router = new Router(admin);

        // Deploy Vault implementation and proxy
        Vault vaultImpl = new Vault();
        bytes memory vaultInitData = abi.encodeWithSelector(
            Vault.initialize.selector,
            admin
        );
        ERC1967Proxy vaultProxy = new ERC1967Proxy(
            address(vaultImpl),
            vaultInitData
        );
        vault = Vault(payable(address(vaultProxy)));

        // Configure Router with MayanRouter
        vm.prank(admin);
        router.setRouter(Route.MAYAN, address(mayanRouter));

        // Configure Vault with Router
        vm.prank(admin);
        vault.setRouter(address(router));

        // Deploy mock token for testing
        token = new MockERC20("Test Token", "TEST", 18);
        token.mint(user, 1000e18);

        vm.deal(user, 100 ether);
    }

    function _signAction(
        Action memory action,
        uint256 privateKey
    ) internal pure returns (bytes memory) {
        bytes32 actionHash = keccak256(abi.encode(action));
        bytes32 messageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", actionHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_ProcessTransfer_ERC20() public {
        // Approve router to spend tokens
        vm.prank(user);
        token.approve(address(mayanRouter), 100e18);

        // Prepare transfer data (gasDrop, deadline)
        bytes memory data = abi.encode(
            uint64(0), // gasDrop
            uint64(0) // deadline (0 = default 1 hour)
        );

        // Create Action object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: 8453, // Base chain ID
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18
        });

        Party[] memory parties = new Party[](0);

        Action memory request = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(user))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(uint256(uint160(address(token)))),
            destinationCaip2ChainId: 1,
            destinationMinTokenAmount: 90e18,
            nonce: 12345,
            expiry: uint128(block.timestamp + 3600)
        });

        uint256 userBalanceBefore = token.balanceOf(user);
        vm.prank(user);
        mayanRouter.processTransfer(request, data);
        uint256 userBalanceAfter = token.balanceOf(user);

        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
    }

    function test_ProcessTransfer_ETH() public {
        // Prepare transfer data for ETH (gasDrop, deadline)
        bytes memory data = abi.encode(
            uint64(0), // gasDrop
            uint64(0) // deadline
        );

        // Create Action object for ETH transfer
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: 8453, // Base chain ID
            contractAddress: bytes32(0), // Native ETH
            value: 1 ether
        });

        Party[] memory parties = new Party[](0);

        Action memory request = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(user))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(0), // ETH
            destinationCaip2ChainId: 1,
            destinationMinTokenAmount: 0.5 ether,
            nonce: 12346,
            expiry: uint128(block.timestamp + 3600)
        });

        uint256 userBalanceBefore = user.balance;
        uint256 swiftV2BalanceBefore = address(SWIFT_V2_BASE).balance;

        // Execute the transfer
        vm.prank(user);
        mayanRouter.processTransfer{value: 1 ether}(request, data);

        // Verify ETH was transferred to the swiftV2
        assertEq(
            address(SWIFT_V2_BASE).balance,
            swiftV2BalanceBefore + 1 ether
        );
        // User balance should decrease by 1 ether (sent to router)
        assertEq(user.balance, userBalanceBefore - 1 ether);
    }

    function test_VaultDepositRouter_ERC20() public {
        // Approve vault to spend tokens
        vm.prank(user);
        token.approve(address(vault), 100e18);

        // Prepare transfer data (gasDrop, deadline)
        bytes memory routeData = abi.encode(
            uint64(0), // gasDrop
            uint64(0) // deadline (0 = default 1 hour)
        );

        // Create Action object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({
            universe: Universe.ETHEREUM,
            address_: bytes32(uint256(uint160(user)))
        });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(uint256(uint160(address(token)))),
            destinationCaip2ChainId: 1,
            destinationMinTokenAmount: 90e18,
            nonce: 1001,
            expiry: uint128(block.timestamp + 3600)
        });

        bytes memory signature = _signAction(action, userPrivateKey);

        console.log("========== INPUTS FOR depositRouter ==========");
        console.log("Action Source ChainID:", action.sources[0].chainID);
        console.log("Action Source Value:", action.sources[0].value);
        console.log("Recipient:", uint256(action.recipientAddress));
        console.log("Dest Namespace Hash:", uint256(action.destinationCaip2namespace));
        console.log("Dest ChainID:", action.destinationCaip2ChainId);
        console.log("Nonce:", uint256(action.nonce));
        console.log("Expiry:", uint256(action.expiry));
        
        console.log("Signature:");
        console.logBytes(signature);
        
        console.log("Chain Index:", uint256(0));
        console.log("Route Enum:", uint256(Route.MAYAN));
        console.log("Route Data:");
        console.logBytes(routeData);

        bytes memory callData = abi.encodeCall(
            Vault.depositRouter,
            (action, signature, 0, Route.MAYAN, routeData)
        );
        console.log("Raw Calldata:");
        console.logBytes(callData);

        uint256 userBalanceBefore = token.balanceOf(user);
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));

        vm.prank(user);
        vault.depositRouter(action, signature, 0, Route.MAYAN, routeData);

        uint256 userBalanceAfter = token.balanceOf(user);
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));

        // User should have transferred tokens to vault
        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
        // Vault should not hold tokens (forwarded to router/mayan)
        assertEq(vaultBalanceBefore, vaultBalanceAfter);
    }

    function test_VaultDepositRouter_ETH() public {
        // Prepare transfer data for ETH (gasDrop, deadline)
        bytes memory routeData = abi.encode(
            uint64(0), // gasDrop
            uint64(0) // deadline
        );

        // Create Action object for ETH transfer
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(0), // Native ETH
            value: 1 ether
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({
            universe: Universe.ETHEREUM,
            address_: bytes32(uint256(uint160(user)))
        });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(0), // ETH
            destinationCaip2ChainId: 1,
            destinationMinTokenAmount: 0.5 ether,
            nonce: 1002,
            expiry: uint128(block.timestamp + 3600)
        });

        bytes memory signature = _signAction(action, userPrivateKey);

        uint256 userBalanceBefore = user.balance;
        uint256 vaultBalanceBefore = address(vault).balance;
        uint256 swiftV2BalanceBefore = address(SWIFT_V2_BASE).balance;

        // Execute the transfer
        vm.prank(user);
        vault.depositRouter{value: 1 ether}(
            action,
            signature,
            0,
            Route.MAYAN,
            routeData
        );

        // Verify ETH was transferred through vault to swiftV2
        assertEq(
            address(SWIFT_V2_BASE).balance,
            swiftV2BalanceBefore + 1 ether
        );
        // User balance should decrease by 1 ether
        assertEq(user.balance, userBalanceBefore - 1 ether);
        // Vault should not hold ETH (forwarded to router/mayan)
        assertEq(address(vault).balance, vaultBalanceBefore);
    }

    function test_VaultDepositRouter_RevertInvalidSignature() public {
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(0),
            value: 1 ether
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({
            universe: Universe.ETHEREUM,
            address_: bytes32(uint256(uint160(user)))
        });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(0),
            destinationCaip2ChainId: 1,
            destinationMinTokenAmount: 0.5 ether,
            nonce: 1003,
            expiry: uint128(block.timestamp + 3600)
        });

        // Sign with wrong private key
        uint256 wrongPrivateKey = 0xBAD;
        bytes memory wrongSignature = _signAction(action, wrongPrivateKey);

        bytes memory routeData = abi.encode(uint64(0), uint64(0));

        vm.prank(user);
        vm.expectRevert("Vault: Invalid signature or from");
        vault.depositRouter{value: 1 ether}(
            action,
            wrongSignature,
            0,
            Route.MAYAN,
            routeData
        );
    }

    function test_VaultDepositRouter_RevertNonceReuse() public {
        vm.prank(user);
        token.approve(address(vault), 200e18);

        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({
            universe: Universe.ETHEREUM,
            address_: bytes32(uint256(uint160(user)))
        });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(uint256(uint160(address(token)))),
            destinationCaip2ChainId: 1,
            destinationMinTokenAmount: 90e18,
            nonce: 2001,
            expiry: uint128(block.timestamp + 3600)
        });

        bytes memory signature = _signAction(action, userPrivateKey);
        bytes memory routeData = abi.encode(uint64(0), uint64(0));

        // First deposit should succeed
        vm.prank(user);
        vault.depositRouter(action, signature, 0, Route.MAYAN, routeData);

        // Second deposit with same nonce should revert
        vm.prank(user);
        vm.expectRevert("Vault: Nonce already used");
        vault.depositRouter(action, signature, 0, Route.MAYAN, routeData);
    }
}
