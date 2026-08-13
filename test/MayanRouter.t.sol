// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {Vault} from "../src/Vault.sol";
import {Executor} from "../src/Executor.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {IMayanForwarder} from "../src/interfaces/IMayanForwarder.sol";
import {IMayanSwiftV2} from "../src/interfaces/IMayanSwiftV2.sol";
import {
    Request,
    SourcePair,
    Party,
    Universe,
    DestinationPair,
    ExternalRequest,
    ExternalSourcePair,
    RoutingPayload
} from "../src/types.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

contract MayanRouterTest is Test {
    MayanRouter public mayanRouter;
    Vault public vault;
    MockERC20 public token;

    address public admin;
    address public verifier;
    address public user;
    uint256 public userPrivateKey;
    address public recipient;
    address public middleware;

    bytes32 public constant MIDDLEWARE_ROLE = keccak256("MIDDLEWARE_ROLE");

    /// @notice True when the fork is pinned to a specific block (BASE_FORK_BLOCK set), enabling
    /// the captured ETH-swap fixture tests which only replay at their capture block
    bool internal forkPinned;

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

    function test_E2E_DepositRouter_ExecutesMayanPayloadOnBaseFork() public {
        vm.createSelectFork("base");

        address ethereumUsdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
        address swiftV2Protocol = 0x40fFE85A28DC9993541449464d7529a922142960;
        uint256 amountIn = 10e6;
        uint64 minAmountOut = 9e6;
        uint256 expiry = block.timestamp + 1 hours;

        Vault vaultImpl = new Vault();
        Vault e2eVault = Vault(
            payable(address(new ERC1967Proxy(address(vaultImpl), abi.encodeCall(Vault.initialize, (admin, verifier)))))
        );

        Executor executor = new Executor(address(e2eVault), address(this));

        // Routing allowlist: only the Mayan forwarder, and only its ERC-20 entry point.
        executor.setTarget(MAYAN_FORWARDER, true);
        executor.setSelector(MAYAN_FORWARDER, IMayanForwarder.forwardERC20.selector, true);

        vm.prank(admin);
        e2eVault.setExecutor(address(executor));

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] =
            DestinationPair({contractAddress: bytes32(uint256(uint160(ethereumUsdc))), value: minAmountOut});
        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        IMayanSwiftV2.OrderParams memory orderParams = IMayanSwiftV2.OrderParams({
            payloadType: 1,
            trader: bytes32(uint256(uint160(user))),
            destAddr: bytes32(uint256(uint160(recipient))),
            destChainId: 2,
            referrerAddr: bytes32(0),
            tokenOut: bytes32(uint256(uint160(ethereumUsdc))),
            minAmountOut: minAmountOut,
            gasDrop: 0,
            cancelFee: 0,
            refundFee: 0,
            deadline: uint64(expiry),
            referrerBps: 0,
            auctionMode: 2,
            random: keccak256("deposit-router-e2e")
        });
        bytes memory protocolData =
            abi.encodeCall(IMayanSwiftV2.createOrderWithToken, (MIDDLE_TOKEN, amountIn, orderParams, bytes("")));
        IMayanForwarder.PermitParams memory emptyPermit;
        bytes memory mayanCallData = abi.encodeCall(
            IMayanForwarder.forwardERC20, (MIDDLE_TOKEN, amountIn, emptyPermit, swiftV2Protocol, protocolData)
        );
        bytes memory payload = abi.encode(
            RoutingPayload({
                protocolTag: "mayan-swift-v2", target: MAYAN_FORWARDER, callData: mayanCallData, arbitaryData: bytes("")
            })
        );

        ExternalSourcePair[] memory externalSources = new ExternalSourcePair[](1);
        externalSources[0] = ExternalSourcePair({
            universe: Universe.ETHEREUM,
            chainID: 8453,
            contractAddress: bytes32(uint256(uint160(MIDDLE_TOKEN))),
            value: amountIn,
            fee: 0,
            payloadHash: keccak256(payload)
        });
        ExternalRequest memory externalRequest = ExternalRequest({
            sources: externalSources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            destinations: destinations,
            nonce: 55_001,
            expiry: expiry,
            parties: parties,
            arbitaryData: bytes("")
        });

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            abi.encodePacked(
                "Sign this intent to proceed \n",
                Strings.toHexString(
                    uint256(
                        keccak256(
                            abi.encode(
                                externalRequest.sources,
                                externalRequest.destinationUniverse,
                                externalRequest.destinationChainID,
                                externalRequest.recipientAddress,
                                externalRequest.destinations,
                                externalRequest.nonce,
                                externalRequest.expiry,
                                externalRequest.parties,
                                externalRequest.arbitaryData
                            )
                        )
                    ),
                    32
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        deal(MIDDLE_TOKEN, user, amountIn);
        vm.prank(user);
        IERC20(MIDDLE_TOKEN).approve(address(e2eVault), amountIn);

        uint256 swiftBalanceBefore = IERC20(MIDDLE_TOKEN).balanceOf(swiftV2Protocol);

        vm.prank(user);
        e2eVault.depositRouter(externalRequest, signature, 0, payload, bytes(""));

        assertTrue(
            e2eVault.depositNonce(uint256(keccak256(abi.encode(uint256(55_001), uint256(0))))),
            "source nonce not consumed"
        );
        assertEq(IERC20(MIDDLE_TOKEN).balanceOf(user), 0, "user source balance");
        assertEq(IERC20(MIDDLE_TOKEN).balanceOf(address(e2eVault)), 0, "Vault source balance");
        assertEq(IERC20(MIDDLE_TOKEN).balanceOf(address(executor)), 0, "Executor source balance");
        assertEq(
            IERC20(MIDDLE_TOKEN).balanceOf(swiftV2Protocol),
            swiftBalanceBefore + amountIn,
            "Mayan Swift did not escrow the source token"
        );
    }

    function setUp() public {
        // Fork Base. By default we fork the latest block, which any public (non-archive) endpoint
        // can serve. Set BASE_FORK_BLOCK to pin a specific block (requires an archive RPC); pinning
        // is only needed to replay the captured ETH-swap fixtures, which were recorded against
        // block 45_268_673 and only execute at their capture block.
        uint256 forkBlock = vm.envOr("BASE_FORK_BLOCK", uint256(0));
        forkPinned = forkBlock != 0;
        if (forkBlock == 0) {
            vm.createSelectFork("base");
        } else {
            vm.createSelectFork("base", forkBlock);
            vm.warp(1_777_326_693);
        }

        admin = makeAddr("admin");
        verifier = makeAddr("verifier");
        userPrivateKey = 0xA11CE;
        user = vm.addr(userPrivateKey);
        recipient = makeAddr("recipient");
        middleware = makeAddr("middleware");

        // Deploy MayanRouter implementation and proxy
        MayanRouter mayanRouterImpl = new MayanRouter();
        (Universe[] memory universes, uint256[] memory chainIds, uint16[] memory wormholeChainIds) =
            _defaultWormholeConfig();
        uint16[] memory tokenWormholeChainIds = new uint16[](0);
        address[] memory tokens = new address[](0);
        uint8[] memory decimals = new uint8[](0);
        bytes memory mayanRouterInitData = abi.encodeWithSelector(
            MayanRouter.initialize.selector,
            admin,
            universes,
            chainIds,
            wormholeChainIds,
            tokenWormholeChainIds,
            tokens,
            decimals
        );
        ERC1967Proxy mayanRouterProxy = new ERC1967Proxy(address(mayanRouterImpl), mayanRouterInitData);
        mayanRouter = MayanRouter(payable(address(mayanRouterProxy)));

        // MayanRouter.initialize grants no AccessControl admin, so grantRole cannot be called
        // until an admin exists. Write DEFAULT_ADMIN_ROLE for admin directly into the ERC-7201
        // namespaced AccessControl storage to simulate the required post-deployment admin grant.
        bytes32 accessControlStorage = 0x02dd7bc7dec4dceedda775e58dd541e08a116c6c53815c0bd028192f7b626800;
        bytes32 adminRoleDataSlot =
            keccak256(abi.encode(mayanRouter.DEFAULT_ADMIN_ROLE(), uint256(accessControlStorage)));
        bytes32 adminHasRoleSlot = keccak256(abi.encode(admin, adminRoleDataSlot));
        vm.store(address(mayanRouter), adminHasRoleSlot, bytes32(uint256(1)));

        // Deploy Vault implementation and proxy
        Vault vaultImpl = new Vault();
        bytes memory vaultInitData = abi.encodeWithSelector(Vault.initialize.selector, admin, verifier);
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), vaultInitData);
        vault = Vault(payable(address(vaultProxy)));

        // Configure Vault with MayanRouter and authorize it to call the router.
        vm.startPrank(admin);
        vault.setRouter(address(mayanRouter));
        vault.grantRole(MIDDLEWARE_ROLE, middleware);
        mayanRouter.grantRole(mayanRouter.VAULT_ROLE(), address(vault));
        vm.stopPrank();

        // Deploy mock token for testing
        token = new MockERC20("Test Token", "TEST");
        token.mint(user, 1000e18);

        vm.prank(admin);
        mayanRouter.setTokenOutDecimals(2, address(token), 18);
        vm.prank(admin);
        mayanRouter.setTokenOutDecimals(2, address(0), 18);
        vm.prank(admin);
        mayanRouter.setTokenOutDecimals(30, address(token), 18);
        vm.prank(admin);
        mayanRouter.setTokenOutDecimals(30, address(0), 18);

        vm.etch(MAYAN_FORWARDER, hex"00");

        vm.deal(user, 100 ether);
        vm.deal(middleware, 100 ether);
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

    function _defaultWormholeConfig()
        internal
        pure
        returns (Universe[] memory universes, uint256[] memory chainIds, uint16[] memory wormholeChainIds)
    {
        universes = new Universe[](7);
        chainIds = new uint256[](7);
        wormholeChainIds = new uint16[](7);

        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 0, 1, 2);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 1, 8453, 30);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 2, 42_161, 23);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 3, 10, 24);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 4, 43_114, 6);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 5, 137, 5);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 6, 56, 4);
    }

    function _setWormholeConfigAt(
        Universe[] memory universes,
        uint256[] memory chainIds,
        uint16[] memory wormholeChainIds,
        uint256 index,
        uint256 chainId,
        uint16 wormholeChainId
    ) internal pure {
        universes[index] = Universe.ETHEREUM;
        chainIds[index] = chainId;
        wormholeChainIds[index] = wormholeChainId;
    }

    function _grantVaultRole(address account) internal {
        vm.startPrank(admin);
        mayanRouter.grantRole(mayanRouter.VAULT_ROLE(), account);
        vm.stopPrank();
    }

    function test_ProcessTransfer_ERC20() public {
        _grantVaultRole(user);

        // Approve router to spend tokens
        vm.prank(user);
        token.approve(address(mayanRouter), 100e18);

        // Prepare V2 transfer data (direct V2 payload encoding, no SwiftVersion wrapper)
        bytes memory data = abi.encode(
            uint16(0), // cancelFee
            uint16(0), // refundFee
            uint64(0), // gasDrop
            bytes32(0), // random
            address(0), // swapProtocol
            bytes(""), // swapData
            address(0), // middleToken
            uint256(0) // minMiddleAmount
        );

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

        // Encode data with chain index
        bytes memory encodedData = abi.encode(uint256(0), data);

        uint256 userBalanceBefore = token.balanceOf(user);
        vm.prank(user);
        mayanRouter.processTransfer(request, encodedData);
        uint256 userBalanceAfter = token.balanceOf(user);

        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
    }

    function test_ProcessTransfer_ERC20_UsesFeePercentages() public {
        _grantVaultRole(user);

        vm.startPrank(admin);
        mayanRouter.setTokenOutDecimals(2, address(token), 18);
        mayanRouter.setCancelFeeBps(100);
        mayanRouter.setRefundFeeBps(250);
        vm.stopPrank();

        vm.prank(user);
        token.approve(address(mayanRouter), 100e18);

        bytes memory data =
            abi.encode(uint16(100), uint16(250), uint64(0), bytes32(0), address(0), bytes(""), address(0), uint256(0));

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

        IMayanSwiftV2.OrderParams memory expectedOrderParams = IMayanSwiftV2.OrderParams({
            payloadType: 1,
            trader: bytes32(uint256(uint160(user))),
            destAddr: bytes32(uint256(uint160(user))),
            destChainId: 2,
            referrerAddr: bytes32(0),
            tokenOut: bytes32(uint256(uint160(address(token)))),
            minAmountOut: 9_000_000_000,
            gasDrop: 0,
            cancelFee: 100,
            refundFee: 250,
            deadline: uint64(request.expiry),
            referrerBps: 0,
            auctionMode: 2,
            random: bytes32(0)
        });
        bytes memory protocolData = abi.encodeWithSelector(
            IMayanSwiftV2.createOrderWithToken.selector, address(token), uint256(100e18), expectedOrderParams, bytes("")
        );
        IMayanForwarder.PermitParams memory emptyPermit;
        bytes memory expectedForwardCall = abi.encodeWithSelector(
            IMayanForwarder.forwardERC20.selector,
            address(token),
            uint256(100e18),
            emptyPermit,
            mayanRouter.SWIFT_V2_PROTOCOL(),
            protocolData
        );

        vm.expectCall(MAYAN_FORWARDER, expectedForwardCall);

        vm.prank(user);
        mayanRouter.processTransfer(request, abi.encode(uint256(0), data));
    }

    /// @notice ERC20 swap-and-bridge: when a swap protocol is provided the router must route through
    /// swapAndForwardERC20 and build the Mayan order against the swapped middle token / minMiddleAmount.
    /// @dev The forwarder is mocked because executing a real swap requires live aggregator calldata for
    /// the input token, which the mock token cannot provide. The assertion verifies routing + encoding.
    function test_ProcessTransfer_ERC20_SwapAndBridge() public {
        _grantVaultRole(user);

        vm.prank(user);
        token.approve(address(mayanRouter), 100e18);

        address swapProtocol = SWAP_PROTOCOL;
        bytes memory swapData = hex"deadbeef";
        address middleToken = MIDDLE_TOKEN; // USDC on Base
        uint256 minMiddleAmount = 250e6;

        bytes memory data = abi.encode(
            uint16(0), uint16(0), uint64(0), bytes32(0), swapProtocol, swapData, middleToken, minMiddleAmount
        );

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
            nonce: 22_345,
            expiry: block.timestamp + 3600,
            parties: parties
        });

        // The order must be created against the middle token, not the input token.
        IMayanSwiftV2.OrderParams memory expectedOrderParams = IMayanSwiftV2.OrderParams({
            payloadType: 1,
            trader: bytes32(uint256(uint160(user))),
            destAddr: bytes32(uint256(uint160(user))),
            destChainId: 2,
            referrerAddr: bytes32(0),
            tokenOut: bytes32(uint256(uint160(address(token)))),
            minAmountOut: 9_000_000_000,
            gasDrop: 0,
            cancelFee: 0,
            refundFee: 0,
            deadline: uint64(request.expiry),
            referrerBps: 0,
            auctionMode: 2,
            random: bytes32(0)
        });
        bytes memory protocolData = abi.encodeWithSelector(
            IMayanSwiftV2.createOrderWithToken.selector, middleToken, minMiddleAmount, expectedOrderParams, bytes("")
        );
        IMayanForwarder.PermitParams memory emptyPermit;
        bytes memory expectedForwardCall = abi.encodeWithSelector(
            IMayanForwarder.swapAndForwardERC20.selector,
            address(token),
            uint256(100e18),
            emptyPermit,
            swapProtocol,
            swapData,
            middleToken,
            minMiddleAmount,
            mayanRouter.SWIFT_V2_PROTOCOL(),
            protocolData
        );

        // Mock the forwarder so the assertion does not depend on executing a real on-chain swap.
        vm.mockCall(MAYAN_FORWARDER, abi.encodeWithSelector(IMayanForwarder.swapAndForwardERC20.selector), bytes(""));
        vm.expectCall(MAYAN_FORWARDER, expectedForwardCall);

        uint256 userBalanceBefore = token.balanceOf(user);
        vm.prank(user);
        mayanRouter.processTransfer(request, abi.encode(uint256(0), data));

        // Input token is pulled from the user into the router before forwarding.
        assertEq(userBalanceBefore - 100e18, token.balanceOf(user));
    }

    uint256 constant SWAP_AMOUNT = 0.187 ether;

    function test_ProcessTransfer_ETH() public {
        vm.skip(!forkPinned, "captured swap fixtures only replay on a pinned fork (archive RPC required)");
        _grantVaultRole(user);

        // Prepare transfer data with real swap params from mainnet tx (direct V2 payload)
        bytes memory data = abi.encode(
            uint16(0), // cancelFee
            uint16(0), // refundFee
            uint64(0), // gasDrop
            bytes32(0), // random
            SWAP_PROTOCOL,
            SWAP_DATA,
            MIDDLE_TOKEN,
            MIN_MIDDLE_AMOUNT
        );

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

        // Encode data with chain index
        bytes memory encodedData = abi.encode(uint256(0), data);

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

        // Prepare route data (direct V2 payload, no SwiftVersion wrapper)
        bytes memory routeData = abi.encode(
            uint16(0), // cancelFee
            uint16(0), // refundFee
            uint64(0), // gasDrop
            bytes32(0), // random
            address(0), // swapProtocol
            bytes(""), // swapData
            address(0), // middleToken
            uint256(0) // minMiddleAmount
        );

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
        vault.depositMayan(request, signature, 0, routeData);

        uint256 userBalanceAfter = token.balanceOf(user);
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));

        // User should have transferred tokens to vault
        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
        // Vault should not hold tokens (forwarded to router/mayan)
        assertEq(vaultBalanceBefore, vaultBalanceAfter);
    }

    function test_VaultDepositRouter_MiddlewareRole_ERC20() public {
        vm.prank(user);
        token.approve(address(vault), 100e18);

        bytes memory routeData =
            abi.encode(uint16(0), uint16(0), uint64(0), bytes32(0), address(0), bytes(""), address(0), uint256(0));

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
            nonce: 1006,
            expiry: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signRequest(request, userPrivateKey);

        vm.prank(middleware);
        vault.depositMayan(request, signature, 0, routeData);

        assertTrue(vault.depositNonce(1006), "Middleware deposit should mark nonce");
    }

    function test_VaultDepositRouter_NonMiddlewareRelayer_Reverts() public {
        address relayer = makeAddr("relayer");

        vm.prank(user);
        token.approve(address(vault), 100e18);

        bytes memory routeData =
            abi.encode(uint16(0), uint16(0), uint64(0), bytes32(0), address(0), bytes(""), address(0), uint256(0));

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
            nonce: 1007,
            expiry: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signRequest(request, userPrivateKey);

        vm.expectRevert("Vault: Invalid Sender");
        vm.prank(relayer);
        vault.depositMayan(request, signature, 0, routeData);
    }

    function test_VaultDepositRouter_ETH() public {
        vm.skip(!forkPinned, "captured swap fixtures only replay on a pinned fork (archive RPC required)");
        // Prepare route data with real swap params (direct V2 payload)
        bytes memory routeData = abi.encode(
            uint16(0), // cancelFee
            uint16(0), // refundFee
            uint64(0), // gasDrop
            bytes32(0), // random
            SWAP_PROTOCOL,
            SWAP_DATA,
            MIDDLE_TOKEN,
            MIN_MIDDLE_AMOUNT
        );

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
        vault.depositMayan{value: SWAP_AMOUNT}(request, signature, 0, routeData);

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

        // Prepare route data (direct V2 payload)
        bytes memory routeData =
            abi.encode(uint16(0), uint16(0), uint64(0), bytes32(0), address(0), bytes(""), address(0), uint256(0));

        vm.prank(user);
        vm.expectRevert("Vault: Invalid signature or from");
        vault.depositMayan{value: 1 ether}(request, wrongSignature, 0, routeData);
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
        bytes memory routeData =
            abi.encode(uint16(0), uint16(0), uint64(0), bytes32(0), address(0), bytes(""), address(0), uint256(0));

        // First deposit should succeed
        vm.prank(user);
        vault.depositMayan(request, signature, 0, routeData);

        // Second deposit with same nonce should revert
        vm.prank(user);
        vm.expectRevert("Vault: Nonce already used");
        vault.depositMayan(request, signature, 0, routeData);
    }

    function test_ProcessTransferV2_ERC20() public {
        _grantVaultRole(user);

        // Approve router to spend tokens
        vm.prank(user);
        token.approve(address(mayanRouter), 100e18);

        // Encode V2 data (direct V2 payload encoding, no SwiftVersion wrapper)
        bytes memory data = abi.encode(
            uint16(0), // cancelFee
            uint16(0), // refundFee
            uint64(0), // gasDrop
            bytes32(0), // random
            address(0), // swapProtocol
            bytes(""), // swapData
            address(0), // middleToken
            uint256(0) // minMiddleAmount
        );

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

        // Encode data with chain index
        bytes memory encodedData = abi.encode(uint256(0), data);

        uint256 userBalanceBefore = token.balanceOf(user);
        vm.prank(user);
        mayanRouter.processTransfer(request, encodedData);
        uint256 userBalanceAfter = token.balanceOf(user);

        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
    }

    function test_ProcessTransferV2_ETH() public {
        vm.skip(!forkPinned, "captured swap fixtures only replay on a pinned fork (archive RPC required)");
        _grantVaultRole(user);

        // Encode V2 data with real swap params from mainnet tx
        bytes memory data = abi.encode(
            uint16(0), // cancelFee
            uint16(0), // refundFee
            uint64(0), // gasDrop
            bytes32(0), // random
            SWAP_PROTOCOL,
            SWAP_DATA,
            MIDDLE_TOKEN,
            MIN_MIDDLE_AMOUNT
        );

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
            nonce: 12_348,
            expiry: block.timestamp + 3600,
            parties: parties
        });

        // Encode data with chain index
        bytes memory encodedData = abi.encode(uint256(0), data);

        uint256 userBalanceBefore = user.balance;

        // Execute the transfer
        vm.prank(user);
        mayanRouter.processTransfer{value: SWAP_AMOUNT}(request, encodedData);

        // User balance should decrease by swap amount (sent to router)
        assertEq(user.balance, userBalanceBefore - SWAP_AMOUNT);
    }

    function test_ProcessTransfer_InvalidVersion() public {
        _grantVaultRole(user);

        // Create invalid data that will fail V2 decode
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

        // Encode data with chain index
        bytes memory encodedData = abi.encode(uint256(0), invalidData);

        vm.prank(user);
        vm.expectRevert();
        mayanRouter.processTransfer{value: 1 ether}(request, encodedData);
    }

    function test_VaultDepositRouter_V2_ERC20() public {
        // Approve vault to spend tokens
        vm.prank(user);
        token.approve(address(vault), 100e18);

        // Encode V2 data (direct V2 payload, no SwiftVersion wrapper)
        bytes memory routeData = abi.encode(
            uint16(0), // cancelFee
            uint16(0), // refundFee
            uint64(0), // gasDrop
            bytes32(0), // random
            address(0), // swapProtocol
            bytes(""), // swapData
            address(0), // middleToken
            uint256(0) // minMiddleAmount
        );

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
        vault.depositMayan(request, signature, 0, routeData);

        uint256 userBalanceAfter = token.balanceOf(user);
        uint256 vaultBalanceAfter = token.balanceOf(address(vault));

        // User should have transferred tokens to vault
        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
        // Vault should not hold tokens (forwarded to router/mayan)
        assertEq(vaultBalanceBefore, vaultBalanceAfter);
    }

    function test_VaultDepositRouter_V2_ETH() public {
        vm.skip(!forkPinned, "captured swap fixtures only replay on a pinned fork (archive RPC required)");
        // Encode V2 data with real swap params from mainnet tx
        bytes memory routeData = abi.encode(
            uint16(0), // cancelFee
            uint16(0), // refundFee
            uint64(0), // gasDrop
            bytes32(0), // random
            SWAP_PROTOCOL,
            SWAP_DATA,
            MIDDLE_TOKEN,
            MIN_MIDDLE_AMOUNT
        );

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
            nonce: 1005,
            expiry: uint64(block.timestamp + 3600)
        });

        bytes memory signature = _signRequest(request, userPrivateKey);

        uint256 userBalanceBefore = user.balance;
        uint256 vaultBalanceBefore = address(vault).balance;

        // Execute the transfer
        vm.prank(user);
        vault.depositMayan{value: SWAP_AMOUNT}(request, signature, 0, routeData);

        // User balance should decrease by swap amount
        assertEq(user.balance, userBalanceBefore - SWAP_AMOUNT);
        // Vault should not hold ETH (forwarded to router/mayan)
        assertEq(address(vault).balance, vaultBalanceBefore);
    }

    function test_ProcessTransfer_RevertsWhenMinAmountOutExceedsUint64() public {
        _grantVaultRole(address(this));

        vm.prank(admin);
        mayanRouter.setTokenOutDecimals(2, address(0), 8);

        uint256 minAmountOut = uint256(type(uint64).max) + 1;
        Request memory request = _createMinAmountRequest(minAmountOut);

        vm.expectRevert(abi.encodeWithSelector(MayanRouter.MinAmountOutTooLarge.selector, minAmountOut));
        mayanRouter.processTransfer(request, abi.encode(uint256(0), _emptyRouteData()));
    }

    function test_ProcessTransfer_AllowsMaxUint64MinAmountOut() public {
        _grantVaultRole(address(this));

        vm.prank(admin);
        mayanRouter.setTokenOutDecimals(2, address(0), 8);

        Request memory request = _createMinAmountRequest(type(uint64).max);

        vm.mockCall(MAYAN_FORWARDER, abi.encodeWithSelector(IMayanForwarder.swapAndForwardEth.selector), bytes(""));
        mayanRouter.processTransfer(request, abi.encode(uint256(0), _emptyRouteData()));
    }

    function test_ProcessTransfer_RevertsWhenNativeMsgValueDoesNotMatchAmountIn() public {
        _grantVaultRole(address(this));

        Request memory request = _createNativeRequest(1 ether);
        vm.deal(address(mayanRouter), 1 ether);

        vm.expectRevert(abi.encodeWithSelector(MayanRouter.InvalidNativeAmount.selector, 1 ether, 0));
        mayanRouter.processTransfer(request, abi.encode(uint256(0), _emptyRouteData()));
    }

    function test_ProcessTransfer_AllowsMatchingNativeMsgValue() public {
        _grantVaultRole(address(this));

        Request memory request = _createNativeRequest(1 ether);

        vm.mockCall(MAYAN_FORWARDER, abi.encodeWithSelector(IMayanForwarder.swapAndForwardEth.selector), bytes(""));
        mayanRouter.processTransfer{value: 1 ether}(request, abi.encode(uint256(0), _emptyRouteData()));
    }

    function test_ProcessTransfer_RevertsWhenCallerLacksVaultRole() public {
        Request memory request = _createNativeRequest(1 ether);
        bytes memory encodedData = abi.encode(uint256(0), _emptyRouteData());

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, user, mayanRouter.VAULT_ROLE()
            )
        );
        vm.prank(user);
        mayanRouter.processTransfer{value: 1 ether}(request, encodedData);
    }

    function _createMinAmountRequest(uint256 minAmountOut) internal view returns (Request memory) {
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM, chainID: block.chainid, contractAddress: bytes32(0), value: 0, fee: 0
        });

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(0), value: minAmountOut});

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        return Request({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: 12_350,
            expiry: block.timestamp + 3600,
            parties: parties
        });
    }

    function _createNativeRequest(uint256 amountIn) internal view returns (Request memory) {
        SourcePair[] memory sources = new SourcePair[](1);
        sources[0] = SourcePair({
            universe: Universe.ETHEREUM, chainID: block.chainid, contractAddress: bytes32(0), value: amountIn, fee: 0
        });

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({contractAddress: bytes32(0), value: 1});

        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        return Request({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: 12_351,
            expiry: block.timestamp + 3600,
            parties: parties
        });
    }

    function _emptyRouteData() internal pure returns (bytes memory) {
        return abi.encode(uint16(0), uint16(0), uint64(0), bytes32(0), address(0), bytes(""), address(0), uint256(0));
    }
}

/// @notice Stand-in for MayanForwarder that accepts and retains the forwarded native value.
/// @dev Etched over the real forwarder so the native leg settles without replaying an on-chain swap.
///      vm.mockCall cannot be used here: it intercepts the call without transferring value, which
///      leaves the balance stranded on the Executor and trips its residual refund path.
contract MayanForwarderNativeStub {
    function swapAndForwardEth(uint256, address, bytes calldata, address, uint256, address, bytes calldata)
        external
        payable {}
}

contract MayanPolygonDeploymentForkTest is Test {
    address private constant VAULT_IMPLEMENTATION = 0xc41C1aD28AdB4301b2abCd1720CDcd7e1F6Dbd6c;
    address private constant VAULT_PROXY = 0x7d4787E6bE280886B9Cc7CD1980B78474c69F98C;
    address private constant EXECUTOR = 0x7cb43713091923b4aAF3478d7514AbB72648188e;
    bytes32 private constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function test_E2E_PolygonDeployment_DepositRouterExecutesMayanForwarderPayload() public {
        vm.createSelectFork("polygon");

        Vault deployedVault = Vault(payable(VAULT_PROXY));
        Executor deployedExecutor = Executor(payable(EXECUTOR));
        address mayanForwarder = 0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;
        address polygonUsdc = 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359;
        address ethereumUsdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
        address swiftV2Protocol = 0x40fFE85A28DC9993541449464d7529a922142960;
        uint256 userPrivateKey = 0xA11CE;
        address user = vm.addr(userPrivateKey);
        address recipient = makeAddr("polygon recipient");
        uint256 amountIn = 10e6;
        uint64 minAmountOut = 9e6;
        uint256 expiry = block.timestamp + 1 hours;

        assertEq(
            address(uint160(uint256(vm.load(address(deployedVault), ERC1967_IMPLEMENTATION_SLOT)))),
            VAULT_IMPLEMENTATION,
            "Vault implementation"
        );
        assertEq(deployedVault.executor(), address(deployedExecutor), "Vault Executor");
        assertEq(deployedExecutor.vault(), address(deployedVault), "Executor Vault");

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] =
            DestinationPair({contractAddress: bytes32(uint256(uint160(ethereumUsdc))), value: minAmountOut});
        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        IMayanSwiftV2.OrderParams memory orderParams = IMayanSwiftV2.OrderParams({
            payloadType: 1,
            trader: bytes32(uint256(uint160(user))),
            destAddr: bytes32(uint256(uint160(recipient))),
            destChainId: 2,
            referrerAddr: bytes32(0),
            tokenOut: bytes32(uint256(uint160(ethereumUsdc))),
            minAmountOut: minAmountOut,
            gasDrop: 0,
            cancelFee: 0,
            refundFee: 0,
            deadline: uint64(expiry),
            referrerBps: 0,
            auctionMode: 2,
            random: keccak256(abi.encode("polygon-deployment-e2e", block.number))
        });
        bytes memory protocolData =
            abi.encodeCall(IMayanSwiftV2.createOrderWithToken, (polygonUsdc, amountIn, orderParams, bytes("")));
        IMayanForwarder.PermitParams memory emptyPermit;
        bytes memory mayanCallData = abi.encodeCall(
            IMayanForwarder.forwardERC20, (polygonUsdc, amountIn, emptyPermit, swiftV2Protocol, protocolData)
        );
        bytes memory payload = abi.encode(
            RoutingPayload({
                protocolTag: "mayan-swift-v2", target: mayanForwarder, callData: mayanCallData, arbitaryData: bytes("")
            })
        );

        ExternalSourcePair[] memory sources = new ExternalSourcePair[](1);
        sources[0] = ExternalSourcePair({
            universe: Universe.ETHEREUM,
            chainID: 137,
            contractAddress: bytes32(uint256(uint160(polygonUsdc))),
            value: amountIn,
            fee: 0,
            payloadHash: keccak256(payload)
        });
        ExternalRequest memory request = ExternalRequest({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            destinations: destinations,
            nonce: uint256(keccak256(abi.encode("polygon-deployment-e2e", block.number))),
            expiry: expiry,
            parties: parties,
            arbitaryData: bytes("")
        });

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            abi.encodePacked(
                "Sign this intent to proceed \n", Strings.toHexString(uint256(_hashExternalRequest(request)), 32)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);

        deal(polygonUsdc, user, amountIn);
        vm.prank(user);
        IERC20(polygonUsdc).approve(address(deployedVault), amountIn);

        uint256 swiftBalanceBefore = IERC20(polygonUsdc).balanceOf(swiftV2Protocol);

        vm.prank(user);
        deployedVault.depositRouter(request, abi.encodePacked(r, s, v), 0, payload, bytes(""));

        assertEq(IERC20(polygonUsdc).balanceOf(user), 0, "user source balance");
        assertEq(IERC20(polygonUsdc).balanceOf(address(deployedVault)), 0, "Vault source balance");
        assertEq(IERC20(polygonUsdc).balanceOf(address(deployedExecutor)), 0, "Executor source balance");
        assertEq(
            IERC20(polygonUsdc).balanceOf(swiftV2Protocol),
            swiftBalanceBefore + amountIn,
            "Mayan Swift did not escrow Polygon USDC"
        );
    }

    function test_E2E_PolygonDeployment_DepositRouterExecutesNativePolMayanForwarderPayload() public {
        vm.createSelectFork("polygon");

        Vault deployedVault = Vault(payable(VAULT_PROXY));
        Executor deployedExecutor = Executor(payable(EXECUTOR));
        address mayanForwarder = 0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;
        address polygonUsdc = 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359;
        address ethereumUsdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
        address swiftV2Protocol = 0x40fFE85A28DC9993541449464d7529a922142960;
        uint256 userPrivateKey = 0xB0B;
        address user = vm.addr(userPrivateKey);
        address recipient = makeAddr("native POL recipient");
        uint256 amountIn = 0.01 ether;
        uint64 minAmountOut = 1;
        uint256 expiry = block.timestamp + 1 hours;

        // Swift V2 has no native entry point, so native input is swapped to a middle token first and
        // the order is created against that token. Mirrors MayanRouter._processTransferV2.
        address swapProtocol = 0x0000000000001fF3684f28c67538d4D072C22734;
        address middleToken = polygonUsdc;
        uint256 minMiddleAmount = 1;
        bytes memory swapData = hex"";

        assertEq(
            address(uint160(uint256(vm.load(address(deployedVault), ERC1967_IMPLEMENTATION_SLOT)))),
            VAULT_IMPLEMENTATION,
            "Vault implementation"
        );
        assertEq(deployedVault.executor(), address(deployedExecutor), "Vault Executor");
        assertEq(deployedExecutor.vault(), address(deployedVault), "Executor Vault");

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] =
            DestinationPair({contractAddress: bytes32(uint256(uint160(ethereumUsdc))), value: minAmountOut});
        Party[] memory parties = new Party[](1);
        parties[0] = Party({universe: Universe.ETHEREUM, address_: bytes32(uint256(uint160(user)))});

        IMayanSwiftV2.OrderParams memory orderParams = IMayanSwiftV2.OrderParams({
            payloadType: 1,
            trader: bytes32(uint256(uint160(user))),
            destAddr: bytes32(uint256(uint160(recipient))),
            destChainId: 2,
            referrerAddr: bytes32(0),
            tokenOut: bytes32(uint256(uint160(ethereumUsdc))),
            minAmountOut: minAmountOut,
            gasDrop: 0,
            cancelFee: 0,
            refundFee: 0,
            deadline: uint64(expiry),
            referrerBps: 0,
            auctionMode: 2,
            random: keccak256(abi.encode("polygon-native-deployment-e2e", block.number))
        });
        bytes memory protocolData =
            abi.encodeCall(IMayanSwiftV2.createOrderWithToken, (middleToken, minMiddleAmount, orderParams, bytes("")));
        bytes memory mayanCallData = abi.encodeCall(
            IMayanForwarder.swapAndForwardEth,
            (amountIn, swapProtocol, swapData, middleToken, minMiddleAmount, swiftV2Protocol, protocolData)
        );
        bytes memory payload = abi.encode(
            RoutingPayload({
                protocolTag: "mayan-swift-v2-native",
                target: mayanForwarder,
                callData: mayanCallData,
                arbitaryData: bytes("")
            })
        );

        ExternalSourcePair[] memory sources = new ExternalSourcePair[](1);
        sources[0] = ExternalSourcePair({
            universe: Universe.ETHEREUM,
            chainID: 137,
            contractAddress: bytes32(0),
            value: amountIn,
            fee: 0,
            payloadHash: keccak256(payload)
        });
        ExternalRequest memory request = ExternalRequest({
            sources: sources,
            destinationUniverse: Universe.ETHEREUM,
            destinationChainID: 1,
            recipientAddress: bytes32(uint256(uint160(recipient))),
            destinations: destinations,
            nonce: uint256(keccak256(abi.encode("polygon-native-deployment-e2e", block.number))),
            expiry: expiry,
            parties: parties,
            arbitaryData: bytes("")
        });

        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            abi.encodePacked(
                "Sign this intent to proceed \n", Strings.toHexString(uint256(_hashExternalRequest(request)), 32)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPrivateKey, digest);

        vm.deal(user, amountIn);
        uint256 forwarderBalanceBefore = mayanForwarder.balance;

        // Stub the forwarder so the assertion does not depend on executing a real on-chain swap,
        // while still consuming the forwarded native value.
        vm.etch(mayanForwarder, address(new MayanForwarderNativeStub()).code);
        vm.expectCall(mayanForwarder, amountIn, mayanCallData);

        vm.prank(user);
        deployedVault.depositRouter{value: amountIn}(request, abi.encodePacked(r, s, v), 0, payload, bytes(""));

        assertEq(user.balance, 0, "user native balance");
        assertEq(address(deployedVault).balance, 0, "Vault native balance");
        assertEq(address(deployedExecutor).balance, 0, "Executor native balance");
        assertEq(
            mayanForwarder.balance, forwarderBalanceBefore + amountIn, "Mayan Forwarder did not receive native POL"
        );
    }

    function _hashExternalRequest(ExternalRequest memory request) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                request.sources,
                request.destinationUniverse,
                request.destinationChainID,
                request.recipientAddress,
                request.destinations,
                request.nonce,
                request.expiry,
                request.parties,
                request.arbitaryData
            )
        );
    }
}
