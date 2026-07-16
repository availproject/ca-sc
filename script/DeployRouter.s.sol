// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {Universe} from "../src/types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployRouter
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy the MayanRouter contract
contract DeployRouter is Script {
    function run() external returns (address router) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);

        MayanRouter implementation = new MayanRouter();
        Universe[] memory universes = new Universe[](0);
        uint256[] memory chainIds = new uint256[](0);
        uint16[] memory wormholeChainIds = new uint16[](0);
        uint16[] memory tokenWormholeChainIds = new uint16[](0);
        address[] memory tokens = new address[](0);
        uint8[] memory decimals = new uint8[](0);
        bytes memory initData = abi.encodeWithSelector(
            MayanRouter.initialize.selector,
            admin,
            universes,
            chainIds,
            wormholeChainIds,
            tokenWormholeChainIds,
            tokens,
            decimals
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        MayanRouter routerContract = MayanRouter(payable(address(proxy)));
        router = address(proxy);

        console.log("MayanRouter implementation deployed at:", address(implementation));
        console.log("MayanRouter proxy deployed at:", router);
        console.log("Admin address:", admin);

        vm.stopBroadcast();

        // Verify deployment
        require(routerContract.owner() == admin, "Ownership not transferred");
        console.log("Deployment verified successfully");

        return router;
    }
}
