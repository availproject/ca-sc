// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Router} from "../src/Router.sol";

/// @title DeployRouter
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy the Router contract (non-upgradeable)
contract DeployRouter is Script {
    function run() external returns (address router) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);
        address deployer = vm.addr(deployerPrivateKey);

        // Deploy Router directly (no proxy)
        // Initialize with deployer to allow configuration if needed
        Router routerContract = new Router(deployer);
        router = address(routerContract);
        
        console.log("Router deployed at:", router);
        console.log("Admin address:", admin);

        if (admin != deployer) {
            routerContract.grantRole(routerContract.DEFAULT_ADMIN_ROLE(), admin);
            routerContract.renounceRole(routerContract.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred Router admin rights to:", admin);
        }

        vm.stopBroadcast();

        // Verify deployment
        require(
            routerContract.hasRole(routerContract.DEFAULT_ADMIN_ROLE(), admin),
            "Admin role not granted"
        );
        console.log("Deployment verified successfully");

        return router;
    }
}
