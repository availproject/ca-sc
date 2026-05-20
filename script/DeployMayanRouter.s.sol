// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {MayanRouter} from "../src/routes/mayan.sol";

/// @title DeployMayanRouter
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy MayanRouter
contract DeployMayanRouter is Script {
    function run() external returns (address mayanRouter) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);

        address deployer = vm.addr(deployerPrivateKey);

        // Deploy MayanRouter
        mayanRouter = address(new MayanRouter(deployer));
        console.log("MayanRouter deployed at:", mayanRouter);

        MayanRouter mayanRouterContract = MayanRouter(mayanRouter);
        if (admin != deployer) {
            mayanRouterContract.transferOwnership(admin);
            console.log("Transferred MayanRouter ownership to:", admin);
        }

        vm.stopBroadcast();

        console.log("Deployment verified successfully");

        return mayanRouter;
    }
}
