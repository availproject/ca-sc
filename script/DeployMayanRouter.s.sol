// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {MayanRouter} from "../../src/routes/mayan.sol";
import {Router} from "../../src/Router.sol";
import {Route} from "../../src/types.sol";

/// @title DeployMayanRouter
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy MayanRouter and configure it in the Router
contract DeployMayanRouter is Script {
    function run() external returns (address mayanRouter) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address routerProxyAddress = vm.envAddress("ROUTER_ADDRESS");

        require(
            routerProxyAddress != address(0),
            "Router address cannot be zero"
        );

        vm.startBroadcast(deployerPrivateKey);

        // Deploy MayanRouter
        mayanRouter = address(new MayanRouter());
        console.log("MayanRouter deployed at:", mayanRouter);

        // Configure Router to use MayanRouter
        Router router = Router(routerProxyAddress);
        router.setRouter(Route.MAYAN, mayanRouter);
        console.log("MayanRouter set in Router for Route.MAYAN");

        vm.stopBroadcast();

        // Verify configuration
        require(
            router.routers(Route.MAYAN) == mayanRouter,
            "MayanRouter not set correctly"
        );
        console.log("Deployment and configuration verified successfully");

        return mayanRouter;
    }
}
