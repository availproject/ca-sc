// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {Action, SourcePair, DestinationPair, Party, Universe} from "../src/types.sol";
import {console} from "forge-std/console.sol";

contract MayanRouterTest is Test {
    MayanRouter public router;
    MockERC20 public token;

    address public user;
    address public recipient;

    // Mayan Protocol addresses on Base
    address constant MAYAN_FORWARDER =
        0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;
    // Swift V2 protocol address on Base
    address constant SWIFT_V2_BASE = 0xc05fb021704D4709c8C058da691fdf4070574685;

    function setUp() public {
        user = makeAddr("user");
        recipient = makeAddr("recipient");

        // Deploy router
        router = new MayanRouter();

        // Configure Swift V2 protocol for Base (chain ID 8453, Wormhole ID 30)
        vm.prank(user); // Assuming user has permission for now
        router.setSwiftV2Protocol(30, SWIFT_V2_BASE);

        // Deploy mock token for testing
        token = new MockERC20("Test Token", "TEST", 18);
        token.mint(user, 1000e18);

        vm.deal(user, 100 ether);
    }

    function test_ProcessTransfer_ERC20() public {
        // Approve router to spend tokens
        vm.prank(user);
        token.approve(address(router), 100e18);

        // Prepare transfer data
        bytes memory data = abi.encode(
            "1", // destChain: Ethereum
            bytes32(uint256(uint160(address(token)))), // destToken
            uint256(90e18), // minAmountOut
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

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({
            contractAddress: bytes32(uint256(uint160(address(token)))),
            value: 90e18
        });

        Party[] memory parties = new Party[](0);

        Action memory request = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: 12345,
            expiry: block.timestamp + 3600,
            parties: parties,
            origin: "test"
        });

        uint256 userBalanceBefore = token.balanceOf(user);
        vm.prank(user);
        router.processTransfer(request, data);
        uint256 userBalanceAfter = token.balanceOf(user);

        assertEq(userBalanceBefore - 100e18, userBalanceAfter);
    }

    function test_ProcessTransfer_ETH() public {

        // Prepare transfer data for ETH
        bytes memory data = abi.encode(
            "1", // destChain: Ethereum (parsed as uint16)
            bytes32(0), // destToken (ETH)
            uint256(0.5 ether), // minAmountOut
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

        DestinationPair[] memory destinations = new DestinationPair[](1);
        destinations[0] = DestinationPair({
            contractAddress: bytes32(0), // ETH
            value: 0.5 ether
        });

        Party[] memory parties = new Party[](0);

        Action memory request = Action({
            sources: sources,
            recipientAddress: bytes32(uint256(uint160(user))),
            destinations: destinations,
            nonce: 12346,
            expiry: block.timestamp + 3600,
            parties: parties,
            origin: "test"
        });

        uint256 userBalanceBefore = user.balance;
        uint256 swiftV2BalanceBefore = address(SWIFT_V2_BASE).balance;

        // Execute the transfer
        vm.prank(user);
        router.processTransfer{value: 1 ether}(request, data);

        // Verify ETH was transferred to the swiftV2
        assertEq(address(SWIFT_V2_BASE).balance, swiftV2BalanceBefore + 1 ether);
        // User balance should decrease by 1 ether (sent to router)
        assertEq(user.balance, userBalanceBefore - 1 ether);
    }

    function test_ParseCAIP2ToWormhole() public {
        // Skip private function test
        vm.skip(true);
    }

}
