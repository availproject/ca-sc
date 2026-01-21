// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { Script } from "forge-std/Script.sol";
import { console } from "forge-std/console.sol";
import { Router } from "../src/Router.sol";
import { Vault } from "../src/Vault.sol";
import { MayanRouter } from "../src/routes/mayan.sol";
import { Route } from "../src/types.sol";
import { Upgrades } from "openzeppelin-foundry-upgrades/Upgrades.sol";

/// @title DeployAll
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy complete system: Router (direct), Vault (proxy), and MayanRouter
contract DeployAll is Script {
    struct DeploymentAddresses {
        address router;
        address vaultProxy;
        address mayanRouter;
        address admin;
    }

    function run() external returns (DeploymentAddresses memory addresses) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        addresses.admin = admin;

        vm.startBroadcast(deployerPrivateKey);
        address deployer = vm.addr(deployerPrivateKey);

        console.log("\n========== Deploying Router ==========");
        // Deploy with deployer as admin first
        Router routerContract = new Router(deployer);
        addresses.router = address(routerContract);
        console.log("Router deployed at:", addresses.router);

        console.log("\n========== Deploying Vault ==========");
        // Initialize with deployer first to allow configuration
        addresses.vaultProxy =
            Upgrades.deployUUPSProxy("Vault.sol", abi.encodeCall(Vault.initialize, (deployer)));
        console.log("Vault proxy:", addresses.vaultProxy);

        Vault vault = Vault(payable(addresses.vaultProxy));
        vault.setRouter(addresses.router);
        console.log("Router set in Vault");

        // If admin is different, transfer control
        if (addresses.admin != deployer) {
            vault.grantRole(vault.DEFAULT_ADMIN_ROLE(), addresses.admin);
            vault.renounceRole(vault.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred Vault admin rights to:", addresses.admin);
        }

        console.log("\n========== Deploying MayanRouter ==========");
        addresses.mayanRouter = address(new MayanRouter());
        console.log("MayanRouter:", addresses.mayanRouter);

        Router router = Router(addresses.router);
        router.setRouter(Route.MAYAN, addresses.mayanRouter);
        console.log("MayanRouter configured in Router");

        MayanRouter mayanRouter = MayanRouter(addresses.mayanRouter);
        if (addresses.admin != deployer) {
            mayanRouter.transferOwnership(addresses.admin);
            console.log("Transferred MayanRouter ownership to:", addresses.admin);
        }

        // Transfer Router admin rights if needed
        if (addresses.admin != deployer) {
            router.grantRole(router.DEFAULT_ADMIN_ROLE(), addresses.admin);
            router.renounceRole(router.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred Router admin rights to:", addresses.admin);
        }

        vm.stopBroadcast();

        console.log("\n========== Verifying Deployment ==========");
        _verifyDeployment(addresses);

        _printSummary(addresses);

        return addresses;
    }

    function _verifyDeployment(DeploymentAddresses memory addresses) internal view {
        Router router = Router(addresses.router);
        Vault vault = Vault(payable(addresses.vaultProxy));

        require(
            router.hasRole(router.DEFAULT_ADMIN_ROLE(), addresses.admin),
            "Router: Admin role not granted"
        );
        require(
            router.routers(Route.MAYAN) == addresses.mayanRouter,
            "Router: MayanRouter not configured"
        );

        require(
            vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), addresses.admin),
            "Vault: Admin role not granted"
        );
        require(address(vault.router()) == addresses.router, "Vault: Router not set");

        console.log("All verifications passed");
    }

    function _printSummary(DeploymentAddresses memory addresses) internal pure {
        console.log("\n========================================");
        console.log("DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("Admin:", addresses.admin);
        console.log("----------------------------------------");
        console.log("Router:", addresses.router);
        console.log("----------------------------------------");
        console.log("Vault Proxy:", addresses.vaultProxy);
        console.log("----------------------------------------");
        console.log("MayanRouter:", addresses.mayanRouter);
        console.log("========================================\n");
    }
}
