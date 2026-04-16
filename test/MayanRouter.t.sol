// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { Test } from "forge-std/Test.sol";
import { MayanRouter } from "../src/routes/mayan.sol";
import { Router } from "../src/Router.sol";
import { Vault } from "../src/Vault.sol";
import { MockERC20 } from "./mocks/MockERC20.sol";
import { Action, RouterAction, SourcePair, Party, Universe, Route } from "../src/types.sol";
import { console } from "forge-std/console.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IMayanForwarder } from "../src/interfaces/IMayanForwarder.sol";
import { IMayanSwiftV2 } from "../src/interfaces/IMayanSwiftV2.sol";
import { IMayanSwiftV1 } from "../src/interfaces/IMayanSwiftV1.sol";
import { SwiftVersion } from "../src/routes/mayan.sol";

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
    address constant MAYAN_FORWARDER = 0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;
    // Swift V2 protocol address on Base
    address constant SWIFT_V2_BASE = 0xc05fb021704D4709c8C058da691fdf4070574685;
    // Swift V1 protocol address on Base
    address constant SWIFT_V1_BASE = 0xC38e4e6A15593f908255214653d3D947CA1c2338;

    function setUp() public {
        vm.createSelectFork("base");

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
        bytes memory vaultInitData = abi.encodeWithSelector(Vault.initialize.selector, admin);
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = Vault(payable(address(vaultProxy)));

        // Configure Router with MayanRouter
        vm.prank(admin);
        router.setRouter(Route.MAYAN, address(mayanRouter));

        // Configure Vault with Router
        vm.prank(admin);
        vault.setRouter(address(router));

        // Deploy mock token for testing
        token = new MockERC20("Test Token", "TEST");
        token.mint(user, 1000e18);

        vm.deal(user, 100 ether);
    }

    function _signAction(Action memory action, uint256 privateKey)
        internal
        pure
        returns (bytes memory)
    {
        bytes32 actionHash = keccak256(abi.encode(action));
        bytes32 messageHash =
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", actionHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_ProcessTransfer_ERC20() public {
        // Approve router to spend tokens
        vm.prank(user);
        token.approve(address(mayanRouter), 100e18);

        // Prepare V2 transfer data (gasDrop, destAddr, referrerAddr, cancelFee, refundFee, referrerBps, auctionMode, random, payloadType)
        bytes memory v2Payload = abi.encode(
            uint64(0), // gasDrop
            bytes32(uint256(uint160(user))), // destAddr
            bytes32(0), // referrerAddr
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0), // random
            uint8(0) // payloadType
        );
        bytes memory data = abi.encode(SwiftVersion.V2, v2Payload);

        // Create RouterAction object
        RouterAction memory request = RouterAction({
            tokenAddress: bytes32(uint256(uint160(address(token)))),
            recipientAddress: bytes32(uint256(uint160(user))),
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(uint256(uint160(address(token)))),
            destinationMinTokenAmount: 90e18,
            amountIn: 100e18,
            destinationCaip2chainId: 1,
            nonce: 12_345,
            deadline: uint64(block.timestamp + 3600)
        });

        uint256 userBalanceBefore = token.balanceOf(user);
        vm.prank(user);
        mayanRouter.processTransfer(request, data);
        uint256 userBalanceAfter = token.balanceOf(user);

        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
    }

    function test_ProcessTransfer_ETH() public {
        // Prepare transfer data
        bytes memory v2Payload = abi.encode(
            uint64(0), // gasDrop
            bytes32(uint256(uint160(user))), // destAddr
            bytes32(0), // referrerAddr
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0), // random
            uint8(0) // payloadType
        );
        bytes memory data = abi.encode(SwiftVersion.V2, v2Payload);

        // Create RouterAction object
        RouterAction memory request = RouterAction({
            tokenAddress: bytes32(0),
            recipientAddress: bytes32(uint256(uint160(user))),
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(0),
            destinationMinTokenAmount: 0.5 ether,
            amountIn: 1 ether,
            destinationCaip2chainId: 1,
            nonce: 12_346,
            deadline: uint64(block.timestamp + 3600)
        });

        uint256 userBalanceBefore = user.balance;
        uint256 swiftV2BalanceBefore = address(SWIFT_V2_BASE).balance;

        // Execute the transfer
        vm.prank(user);
        mayanRouter.processTransfer{ value: 1 ether }(request, data);

        // Verify ETH was transferred to the swiftV2
        assertEq(address(SWIFT_V2_BASE).balance, swiftV2BalanceBefore + 1 ether);
        // User balance should decrease by 1 ether (sent to router)
        assertEq(user.balance, userBalanceBefore - 1 ether);
    }

    function test_VaultDepositRouter_ERC20() public {
        // Approve vault to spend tokens
        vm.prank(user);
        token.approve(address(vault), 100e18);

        // Prepare route data
        bytes memory v2Payload = abi.encode(
            uint64(0), // gasDrop
            bytes32(uint256(uint160(recipient))), // destAddr
            bytes32(0), // referrerAddr
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0), // random
            uint8(0) // payloadType
        );
        bytes memory routeData = abi.encode(SwiftVersion.V2, v2Payload);

        // Create Action object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18
        });

        Party[] memory parties = new Party[](1);
        parties[0] =
            Party({ universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user))) });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(uint256(uint160(address(token)))),
            destinationCaip2chainId: 1,
            destinationMinTokenAmount: 90e18,
            nonce: 1001,
            deadline: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signAction(action, userPrivateKey);

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
        // Prepare route data
        bytes memory v2Payload = abi.encode(
            uint64(0), // gasDrop
            bytes32(uint256(uint160(recipient))), // destAddr
            bytes32(0), // referrerAddr
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0), // random
            uint8(0) // payloadType
        );
        bytes memory routeData = abi.encode(SwiftVersion.V2, v2Payload);

        // Create Action object for ETH transfer
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(0), // Native ETH
            value: 1 ether
        });

        Party[] memory parties = new Party[](1);
        parties[0] =
            Party({ universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user))) });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(0), // ETH
            destinationCaip2chainId: 1,
            destinationMinTokenAmount: 0.5 ether,
            nonce: 1002,
            deadline: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signAction(action, userPrivateKey);

        uint256 userBalanceBefore = user.balance;
        uint256 vaultBalanceBefore = address(vault).balance;
        uint256 swiftV2BalanceBefore = address(SWIFT_V2_BASE).balance;

        // Execute the transfer
        vm.prank(user);
        vault.depositRouter{ value: 1 ether }(action, signature, 0, Route.MAYAN, routeData);

        // Verify ETH was transferred through vault to swiftV2
        assertEq(address(SWIFT_V2_BASE).balance, swiftV2BalanceBefore + 1 ether);
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
        parties[0] =
            Party({ universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user))) });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(0),
            destinationCaip2chainId: 1,
            destinationMinTokenAmount: 0.5 ether,
            nonce: 1003,
            deadline: uint64(block.timestamp + 3600)
        });

        // Sign with wrong private key
        uint256 wrongPrivateKey = 0xBAD;
        bytes memory wrongSignature = _signAction(action, wrongPrivateKey);

        bytes memory v2Payload = abi.encode(
            uint64(0),
            bytes32(0),
            bytes32(0),
            uint64(0),
            uint64(0),
            uint8(0),
            uint8(0),
            bytes32(0),
            uint8(0)
        );
        bytes memory routeData = abi.encode(SwiftVersion.V2, v2Payload);

        vm.prank(user);
        vm.expectRevert("Vault: Invalid signature or from");
        vault.depositRouter{ value: 1 ether }(action, wrongSignature, 0, Route.MAYAN, routeData);
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
        parties[0] =
            Party({ universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user))) });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(uint256(uint160(address(token)))),
            destinationCaip2chainId: 1,
            destinationMinTokenAmount: 90e18,
            nonce: 2001,
            deadline: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signAction(action, userPrivateKey);
        bytes memory v2Payload = abi.encode(
            uint64(0),
            bytes32(0),
            bytes32(0),
            uint64(0),
            uint64(0),
            uint8(0),
            uint8(0),
            bytes32(0),
            uint8(0)
        );
        bytes memory routeData = abi.encode(SwiftVersion.V2, v2Payload);

        // First deposit should succeed
        vm.prank(user);
        vault.depositRouter(action, signature, 0, Route.MAYAN, routeData);

        // Second deposit with same nonce should revert
        vm.prank(user);
        vm.expectRevert("Vault: Nonce already used");
        vault.depositRouter(action, signature, 0, Route.MAYAN, routeData);
    }

    function test_ProcessTransferV1_ERC20() public {
        // Approve router to spend tokens
        vm.prank(user);
        token.approve(address(mayanRouter), 100e18);

        // Encode V1 data with SwiftVersion.V1 prepended
        bytes memory v1Payload = abi.encode(
            bytes32(uint256(uint160(user))), // trader
            bytes32(uint256(uint160(address(token)))), // tokenOut
            uint64(90), // minAmountOut
            uint64(0), // gasDrop
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint64(block.timestamp + 3600), // deadline
            bytes32(uint256(uint160(user))), // destAddr
            uint16(0), // destChainId
            bytes32(0), // referrerAddr
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0) // random
        );
        bytes memory data = abi.encode(SwiftVersion.V1, v1Payload);

        // Create RouterAction object
        RouterAction memory request = RouterAction({
            tokenAddress: bytes32(uint256(uint160(address(token)))),
            recipientAddress: bytes32(uint256(uint160(user))),
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(uint256(uint160(address(token)))),
            destinationMinTokenAmount: 90e18,
            amountIn: 100e18,
            destinationCaip2chainId: 1,
            nonce: 12_347,
            deadline: uint64(block.timestamp + 3600)
        });

        uint256 userBalanceBefore = token.balanceOf(user);
        vm.prank(user);
        mayanRouter.processTransfer(request, data);
        uint256 userBalanceAfter = token.balanceOf(user);

        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
    }

    function test_ProcessTransferV1_ETH() public {
        // Encode V1 data with SwiftVersion.V1 prepended
        bytes memory v1Payload = abi.encode(
            bytes32(uint256(uint160(user))), // trader
            bytes32(0), // tokenOut
            uint64(50), // minAmountOut
            uint64(0), // gasDrop
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint64(block.timestamp + 3600), // deadline
            bytes32(uint256(uint160(user))), // destAddr
            uint16(0), // destChainId
            bytes32(0), // referrerAddr
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0) // random
        );
        bytes memory data = abi.encode(SwiftVersion.V1, v1Payload);

        // Create RouterAction object
        RouterAction memory request = RouterAction({
            tokenAddress: bytes32(0),
            recipientAddress: bytes32(uint256(uint160(user))),
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(0),
            destinationMinTokenAmount: 0.5 ether,
            amountIn: 1 ether,
            destinationCaip2chainId: 1,
            nonce: 12_348,
            deadline: uint64(block.timestamp + 3600)
        });

        uint256 userBalanceBefore = user.balance;
        uint256 swiftV1BalanceBefore = address(SWIFT_V1_BASE).balance;

        // Execute the transfer
        vm.prank(user);
        mayanRouter.processTransfer{ value: 1 ether }(request, data);

        // Verify ETH was transferred to the swiftV1
        assertEq(address(SWIFT_V1_BASE).balance, swiftV1BalanceBefore + 1 ether);
        // User balance should decrease by 1 ether (sent to router)
        assertEq(user.balance, userBalanceBefore - 1 ether);
    }

    function test_ProcessTransfer_InvalidVersion() public {
        // Create invalid version by encoding a uint8 value > 1
        // This will cause the version check to fail
        bytes memory invalidData = abi.encode(uint8(2), bytes(""));

        // Create RouterAction object
        RouterAction memory request = RouterAction({
            tokenAddress: bytes32(0),
            recipientAddress: bytes32(uint256(uint160(user))),
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(0),
            destinationMinTokenAmount: 0.5 ether,
            amountIn: 1 ether,
            destinationCaip2chainId: 1,
            nonce: 12_349,
            deadline: uint64(block.timestamp + 3600)
        });

        vm.prank(user);
        vm.expectRevert();
        mayanRouter.processTransfer{ value: 1 ether }(request, invalidData);
    }

    function test_VaultDepositRouter_V1_ERC20() public {
        // Approve vault to spend tokens
        vm.prank(user);
        token.approve(address(vault), 100e18);

        // Encode V1 data with SwiftVersion.V1 prepended
        bytes memory v1Payload = abi.encode(
            bytes32(uint256(uint160(recipient))), // trader
            bytes32(uint256(uint160(address(token)))), // tokenOut
            uint64(90), // minAmountOut
            uint64(0), // gasDrop
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint64(block.timestamp + 3600), // deadline
            bytes32(uint256(uint160(recipient))), // destAddr
            uint16(0), // destChainId
            bytes32(0), // referrerAddr
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0) // random
        );
        bytes memory routeData = abi.encode(SwiftVersion.V1, v1Payload);

        // Create Action object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18
        });

        Party[] memory parties = new Party[](1);
        parties[0] =
            Party({ universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user))) });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(uint256(uint160(address(token)))),
            destinationCaip2chainId: 1,
            destinationMinTokenAmount: 90e18,
            nonce: 1004,
            deadline: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signAction(action, userPrivateKey);

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

    function test_VaultDepositRouter_V1_ETH() public {
        // Encode V1 data with SwiftVersion.V1 prepended
        bytes memory v1Payload = abi.encode(
            bytes32(uint256(uint160(recipient))), // trader
            bytes32(0), // tokenOut
            uint64(50), // minAmountOut
            uint64(0), // gasDrop
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint64(block.timestamp + 3600), // deadline
            bytes32(uint256(uint160(recipient))), // destAddr
            uint16(0), // destChainId
            bytes32(0), // referrerAddr
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0) // random
        );
        bytes memory routeData = abi.encode(SwiftVersion.V1, v1Payload);

        // Create Action object for ETH transfer
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(0), // Native ETH
            value: 1 ether
        });

        Party[] memory parties = new Party[](1);
        parties[0] =
            Party({ universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user))) });

        Action memory action = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationCaip2namespace: keccak256("eip155"),
            destinationContractAddress: bytes32(0), // ETH
            destinationCaip2chainId: 1,
            destinationMinTokenAmount: 0.5 ether,
            nonce: 1005,
            deadline: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signAction(action, userPrivateKey);

        uint256 userBalanceBefore = user.balance;
        uint256 vaultBalanceBefore = address(vault).balance;
        uint256 swiftV1BalanceBefore = address(SWIFT_V1_BASE).balance;

        // Execute the transfer
        vm.prank(user);
        vault.depositRouter{ value: 1 ether }(action, signature, 0, Route.MAYAN, routeData);

        // Verify ETH was transferred through vault to swiftV1
        assertEq(address(SWIFT_V1_BASE).balance, swiftV1BalanceBefore + 1 ether);
        // User balance should decrease by 1 ether
        assertEq(user.balance, userBalanceBefore - 1 ether);
        // Vault should not hold ETH (forwarded to router/mayan)
        assertEq(address(vault).balance, vaultBalanceBefore);
    }
}
