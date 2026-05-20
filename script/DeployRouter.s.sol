// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {MayanRouter} from "../src/routes/mayan.sol";

/// @title DeployRouter
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy the MayanRouter contract
contract DeployRouter is Script {
    function run() external returns (address router) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);
        address deployer = vm.addr(deployerPrivateKey);

        // Deploy MayanRouter directly
        MayanRouter routerContract = new MayanRouter(deployer);
        router = address(routerContract);

        console.log("MayanRouter deployed at:", router);
        console.log("Admin address:", admin);

        if (admin != deployer) {
            routerContract.transferOwnership(admin);
            console.log("Transferred MayanRouter ownership to:", admin);
        }

        vm.stopBroadcast();

        // Verify deployment
        require(routerContract.owner() == admin, "Ownership not transferred");
        console.log("Deployment verified successfully");

        return router;
    }
}
