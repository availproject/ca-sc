// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {Router} from "../src/Router.sol";
import {Vault} from "../src/Vault.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {Request, SourcePair, Party, Universe, Route, DestinationPair} from "../src/types.sol";
import {SwiftVersion} from "../src/routes/mayan.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

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

    // Real swap parameters from Base tx
    address constant SWAP_PROTOCOL = 0x0000000000001fF3684f28c67538d4D072C22734;
    address constant MIDDLE_TOKEN = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    uint256 constant MIN_MIDDLE_AMOUNT = 426303507;
    bytes constant SWAP_DATA =
        hex"2213bc0b0000000000000000000000007747f8d2a76bd6345cc29622a946a929647f2359000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002985b825cff80000000000000000000000000007747f8d2a76bd6345cc29622a946a929647f235900000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000009241fff991f000000000000000000000000337685fdab40d39bd02028545a4ffa7d287cc3e2000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda02913000000000000000000000000000000000000000000000000000000001984bf3300000000000000000000000000000000000000000000000000000000000000a0fd0aba5d02eb31646adca10d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000003a000000000000000000000000000000000000000000000000000000000000005a000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000044bd01c2260000000000000000000000000000000000000000000000000000000069efdb8b00000000000000000000000000000000000000000000000002985b825cff800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010438c9c147000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee00000000000000000000000000000000000000000000000000000000000027100000000000000000000000004200000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000024d0e30db00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e48d68a1560000000000000000000000007747f8d2a76bd6345cc29622a946a929647f23590000000000000000000000000000000000000000000000000000000000000ef90000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000404200000000000000000000000000000000000006040000c8fffd8963efd1fc6a506488495d951d5263988d250b3e328455c4059eeb9e3f84b5543f74e24e7e1b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c438c9c1470000000000000000000000004200000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000271000000000000000000000000055555522005bcae1c2424d474bfd5ed477749e3e000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e43ae8b2980000000000000000000000004200000000000000000000000000000000000006000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda029130000000000000000000000000000000000000000000000000199afe5b9594aa0000000000000000000000000000000000000000000000000000000000fb7365d0000000000000000000000007747f8d2a76bd6345cc29622a946a929647f235900000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c438c9c1470000000000000000000000000b3e328455c4059eeb9e3f84b5543f74e24e7e1b000000000000000000000000000000000000000000000000000000000000271000000000000000000000000055555522005bcae1c2424d474bfd5ed477749e3e000000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e43ae8b2980000000000000000000000000b3e328455c4059eeb9e3f84b5543f74e24e7e1b000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda0291300000000000000000000000000000000000000000000000cd9363105af0a80000000000000000000000000000000000000000000000000000000000009c5203e0000000000000000000000007747f8d2a76bd6345cc29622a946a929647f235900000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008434ee90ca000000000000000000000000f5c4f3dc02c3fb9279495a8fef7b0741da956157000000000000000000000000833589fcd6edb6e08f4c7c32d4f71b54bda029130000000000000000000000000000000000000000000000000000000019896ad500000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    function setUp() public {
        vm.createSelectFork("base", 45268673);
        vm.warp(1777326693);

        admin = makeAddr("admin");
        userPrivateKey = 0xA11CE;
        user = vm.addr(userPrivateKey);
        recipient = makeAddr("recipient");

        // Deploy MayanRouter
        mayanRouter = new MayanRouter(admin);

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

    function _signRequest(Request memory request, uint256 privateKey) internal pure returns (bytes memory) {
        bytes32 requestHash = keccak256(
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
        bytes memory msgBytes =
            abi.encodePacked("Sign this intent to proceed \n", Strings.toHexString(uint256(requestHash), 32));
        bytes32 signedMessageHash = MessageHashUtils.toEthSignedMessageHash(msgBytes);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, signedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function test_ProcessTransfer_ERC20() public {
        // Approve router to spend tokens
        vm.prank(user);
        token.approve(address(mayanRouter), 100e18);

        // Prepare V2 transfer data (tokenOutDecimals, gasDrop, destAddr, referrerAddr, cancelFee, refundFee, deadline, referrerBps, auctionMode, random, payloadType)
        bytes memory v2Payload = abi.encode(
            uint8(0), // tokenOutDecimals
            uint64(0), // gasDrop
            bytes32(uint256(uint160(user))), // destAddr
            bytes32(0), // referrerAddr
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint64(block.timestamp + 3600), // deadline
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0), // random
            uint8(0), // payloadType
            address(0), // swapProtocol
            bytes(""), // swapData
            address(0), // middleToken
            uint256(0) // minMiddleAmount
        );
        bytes memory data = abi.encode(SwiftVersion.V2, v2Payload);

        // Create Request object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: 8453,
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18,
            fee: 0
        });

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(uint256(uint160(address(token)))), value: 90e18});

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        Request memory request = Request({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: 12_345,
            expiry: block.timestamp + 3600,
            parties: parties
        });

        // Encode data with chain indices
        bytes memory encodedData = abi.encode(uint256(0), uint256(0), data);

        uint256 userBalanceBefore = token.balanceOf(user);
        vm.prank(user);
        mayanRouter.processTransfer(request, encodedData);
        uint256 userBalanceAfter = token.balanceOf(user);

        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
    }

    uint256 constant SWAP_AMOUNT = 0.187 ether;

    function test_ProcessTransfer_ETH() public {
        // Prepare transfer data with real swap params from mainnet tx
        bytes memory v2Payload = abi.encode(
            uint8(0), // tokenOutDecimals
            uint64(0), // gasDrop
            bytes32(uint256(uint160(user))), // destAddr
            bytes32(0), // referrerAddr
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint64(block.timestamp + 3600), // deadline
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0), // random
            uint8(0), // payloadType
            SWAP_PROTOCOL,
            SWAP_DATA,
            MIDDLE_TOKEN,
            MIN_MIDDLE_AMOUNT
        );
        bytes memory data = abi.encode(SwiftVersion.V2, v2Payload);

        // Create Request object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM, chainID: 8453, contractAddress: bytes32(0), value: SWAP_AMOUNT, fee: 0
        });

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(0), value: 0.5 ether});

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        Request memory request = Request({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: 12_346,
            expiry: block.timestamp + 3600,
            parties: parties
        });

        // Encode data with chain indices
        bytes memory encodedData = abi.encode(uint256(0), uint256(0), data);

        uint256 userBalanceBefore = user.balance;

        // Execute the transfer - should not revert with real swap params
        vm.prank(user);
        mayanRouter.processTransfer{value: SWAP_AMOUNT}(request, encodedData);

        // User balance should decrease by swap amount (sent to router)
        assertEq(user.balance, userBalanceBefore - SWAP_AMOUNT);
    }

    function test_VaultDepositRouter_ERC20() public {
        // Approve vault to spend tokens
        vm.prank(user);
        token.approve(address(vault), 100e18);

        // Prepare route data
        bytes memory v2Payload = abi.encode(
            uint8(0), // tokenOutDecimals
            uint64(0), // gasDrop
            bytes32(uint256(uint160(recipient))), // destAddr
            bytes32(0), // referrerAddr
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint64(block.timestamp + 3600), // deadline
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0), // random
            uint8(0), // payloadType
            address(0), // swapProtocol
            bytes(""), // swapData
            address(0), // middleToken
            uint256(0) // minMiddleAmount
        );
        bytes memory routeData = abi.encode(SwiftVersion.V2, v2Payload);

        // Create Request object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18,
            fee: 0
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(uint256(uint160(address(token)))), value: 90e18});

        Request memory request = Request({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationUniverse: Universe.ETHEREUM,
            destinations: destinations,
            destinationChainID: 1,
            nonce: 1001,
            expiry: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signRequest(request, userPrivateKey);

        uint256 userBalanceBefore = token.balanceOf(user);
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));

        vm.prank(user);
        vault.depositRouter(request, signature, 0, 0, Route.MAYAN, routeData);

        uint256 userBalanceAfter = token.balanceOf(user);
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));

        // User should have transferred tokens to vault
        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
        // Vault should not hold tokens (forwarded to router/mayan)
        assertEq(vaultBalanceBefore, vaultBalanceAfter);
    }

    function test_VaultDepositRouter_ETH() public {
        // Prepare route data with real swap params from mainnet tx
        bytes memory v2Payload = abi.encode(
            uint8(0), // tokenOutDecimals
            uint64(0), // gasDrop
            bytes32(uint256(uint160(recipient))), // destAddr
            bytes32(0), // referrerAddr
            uint64(0), // cancelFee
            uint64(0), // refundFee
            uint64(block.timestamp + 3600), // deadline
            uint8(0), // referrerBps
            uint8(0), // auctionMode
            bytes32(0), // random
            uint8(0), // payloadType
            SWAP_PROTOCOL,
            SWAP_DATA,
            MIDDLE_TOKEN,
            MIN_MIDDLE_AMOUNT
        );
        bytes memory routeData = abi.encode(SwiftVersion.V2, v2Payload);

        // Create Request object for ETH transfer
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(0), // Native ETH
            value: SWAP_AMOUNT,
            fee: 0
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({
            contractAddress: bytes32(0), // ETH
            value: 0.5 ether
        });

        Request memory request = Request({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationUniverse: Universe.ETHEREUM,
            destinations: destinations,
            destinationChainID: 1,
            nonce: 1002,
            expiry: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signRequest(request, userPrivateKey);

        uint256 userBalanceBefore = user.balance;
        uint256 vaultBalanceBefore = address(vault).balance;

        // Execute the transfer - should not revert with real swap params
        vm.prank(user);
        vault.depositRouter{value: SWAP_AMOUNT}(request, signature, 0, 0, Route.MAYAN, routeData);

        // User balance should decrease by swap amount
        assertEq(user.balance, userBalanceBefore - SWAP_AMOUNT);
        // Vault should not hold ETH (forwarded to router/mayan)
        assertEq(address(vault).balance, vaultBalanceBefore);
    }

    function test_VaultDepositRouter_RevertInvalidSignature() public {
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM, chainID: block.chainid, contractAddress: bytes32(0), value: 1 ether, fee: 0
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(0), value: 0.5 ether});

        Request memory request = Request({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationUniverse: Universe.ETHEREUM,
            destinations: destinations,
            destinationChainID: 1,
            nonce: 1003,
            expiry: uint64(block.timestamp + 3600)
        });

        // Sign with wrong private key
        uint256 wrongPrivateKey = 0xBAD;
        bytes memory wrongSignature = _signRequest(request, wrongPrivateKey);

        bytes memory v2Payload = abi.encode(
            uint8(0), // tokenOutDecimals
            uint64(0),
            bytes32(0),
            bytes32(0),
            uint64(0),
            uint64(0),
            uint64(block.timestamp + 3600),
            uint8(0),
            uint8(0),
            bytes32(0),
            uint8(0),
            address(0),
            bytes(""),
            address(0),
            uint256(0)
        );
        bytes memory routeData = abi.encode(SwiftVersion.V2, v2Payload);

        vm.prank(user);
        vm.expectRevert("Vault: Invalid signature or from");
        vault.depositRouter{value: 1 ether}(request, wrongSignature, 0, 0, Route.MAYAN, routeData);
    }

    function test_VaultDepositRouter_RevertNonceReuse() public {
        vm.prank(user);
        token.approve(address(vault), 200e18);

        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18,
            fee: 0
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(uint256(uint160(address(token)))), value: 90e18});

        Request memory request = Request({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationUniverse: Universe.ETHEREUM,
            destinations: destinations,
            destinationChainID: 1,
            nonce: 2001,
            expiry: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signRequest(request, userPrivateKey);
        bytes memory v2Payload = abi.encode(
            uint8(0), // tokenOutDecimals
            uint64(0),
            bytes32(0),
            bytes32(0),
            uint64(0),
            uint64(0),
            uint64(block.timestamp + 3600),
            uint8(0),
            uint8(0),
            bytes32(0),
            uint8(0),
            address(0),
            bytes(""),
            address(0),
            uint256(0)
        );
        bytes memory routeData = abi.encode(SwiftVersion.V2, v2Payload);

        // First deposit should succeed
        vm.prank(user);
        vault.depositRouter(request, signature, 0, 0, Route.MAYAN, routeData);

        // Second deposit with same nonce should revert
        vm.prank(user);
        vm.expectRevert("Vault: Nonce already used");
        vault.depositRouter(request, signature, 0, 0, Route.MAYAN, routeData);
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

        // Create Request object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: 8453,
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18,
            fee: 0
        });

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(uint256(uint160(address(token)))), value: 90e18});

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        Request memory request = Request({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: 12_347,
            expiry: block.timestamp + 3600,
            parties: parties
        });

        // Encode data with chain indices
        bytes memory encodedData = abi.encode(uint256(0), uint256(0), data);

        uint256 userBalanceBefore = token.balanceOf(user);
        vm.prank(user);
        mayanRouter.processTransfer(request, encodedData);
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

        // Create Request object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM, chainID: 8453, contractAddress: bytes32(0), value: 1 ether, fee: 0
        });

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(0), value: 0.5 ether});

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        Request memory request = Request({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: 12_348,
            expiry: block.timestamp + 3600,
            parties: parties
        });

        // Encode data with chain indices
        bytes memory encodedData = abi.encode(uint256(0), uint256(0), data);

        uint256 userBalanceBefore = user.balance;
        uint256 swiftV1BalanceBefore = address(SWIFT_V1_BASE).balance;

        // Execute the transfer
        vm.prank(user);
        mayanRouter.processTransfer{value: 1 ether}(request, encodedData);

        // Verify ETH was transferred to the swiftV1
        assertEq(address(SWIFT_V1_BASE).balance, swiftV1BalanceBefore + 1 ether);
        // User balance should decrease by 1 ether (sent to router)
        assertEq(user.balance, userBalanceBefore - 1 ether);
    }

    function test_ProcessTransfer_InvalidVersion() public {
        // Create invalid version by encoding a uint8 value > 1
        // This will cause the version check to fail
        bytes memory invalidData = abi.encode(uint8(2), bytes(""));

        // Create Request object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM, chainID: 8453, contractAddress: bytes32(0), value: 1 ether, fee: 0
        });

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(0), value: 0.5 ether});

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        Request memory request = Request({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: 12_349,
            expiry: block.timestamp + 3600,
            parties: parties
        });

        // Encode data with chain indices
        bytes memory encodedData = abi.encode(uint256(0), uint256(0), invalidData);

        vm.prank(user);
        vm.expectRevert();
        mayanRouter.processTransfer{value: 1 ether}(request, encodedData);
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

        // Create Request object
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 100e18,
            fee: 0
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(uint256(uint160(address(token)))), value: 90e18});

        Request memory request = Request({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationUniverse: Universe.ETHEREUM,
            destinations: destinations,
            destinationChainID: 1,
            nonce: 1004,
            expiry: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signRequest(request, userPrivateKey);

        uint256 userBalanceBefore = token.balanceOf(user);
        uint256 vaultBalanceBefore = token.balanceOf(address(vault));

        vm.prank(user);
        vault.depositRouter(request, signature, 0, 0, Route.MAYAN, routeData);

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

        // Create Request object for ETH transfer
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: bytes32(0), // Native ETH
            value: 1 ether,
            fee: 0
        });

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({
            contractAddress: bytes32(0), // ETH
            value: 0.5 ether
        });

        Request memory request = Request({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            parties: parties,
            destinationUniverse: Universe.ETHEREUM,
            destinations: destinations,
            destinationChainID: 1,
            nonce: 1005,
            expiry: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signRequest(request, userPrivateKey);

        uint256 userBalanceBefore = user.balance;
        uint256 vaultBalanceBefore = address(vault).balance;
        uint256 swiftV1BalanceBefore = address(SWIFT_V1_BASE).balance;

        // Execute the transfer
        vm.prank(user);
        vault.depositRouter{value: 1 ether}(request, signature, 0, 0, Route.MAYAN, routeData);

        // Verify ETH was transferred through vault to swiftV1
        assertEq(address(SWIFT_V1_BASE).balance, swiftV1BalanceBefore + 1 ether);
        // User balance should decrease by 1 ether
        assertEq(user.balance, userBalanceBefore - 1 ether);
        // Vault should not hold ETH (forwarded to router/mayan)
        assertEq(address(vault).balance, vaultBalanceBefore);
    }
}
