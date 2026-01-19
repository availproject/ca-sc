// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Router} from "../../src/Router.sol";
import {Vault} from "../../src/Vault.sol";
import {MayanRouter} from "../../src/routes/mayan.sol";
import {Route} from "../../src/types.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployAll
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy complete system: Router (direct), Vault (proxy), and MayanRouter
contract DeployAll is Script {
    struct DeploymentAddresses {
        address router;
        address vaultProxy;
        address vaultImplementation;
        address mayanRouter;
        address admin;
    }

    function run() external returns (DeploymentAddresses memory addresses) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        addresses.admin = admin;

        vm.startBroadcast(deployerPrivateKey);

        // ========== Deploy Router (Direct) ==========
        console.log("\n========== Deploying Router ==========");
        Router routerContract = new Router(admin);
        addresses.router = address(routerContract);
        console.log("Router deployed at:", addresses.router);

        // ========== Deploy Vault (Proxy) ==========
        console.log("\n========== Deploying Vault ==========");
        addresses.vaultImplementation = address(new Vault());
        console.log(
            "Vault implementation:",
            addresses.vaultImplementation
        );

        bytes memory vaultInitData = abi.encodeWithSelector(
            Vault.initialize.selector,
            admin
        );

        addresses.vaultProxy = address(
            new ERC1967Proxy(addresses.vaultImplementation, vaultInitData)
        );
        console.log("Vault proxy:", addresses.vaultProxy);

        // Set Router in Vault
        Vault vault = Vault(payable(addresses.vaultProxy));
        vault.setRouter(addresses.router);
        console.log("Router set in Vault");

        // ========== Deploy MayanRouter ==========
        console.log("\n========== Deploying MayanRouter ==========");
        addresses.mayanRouter = address(new MayanRouter());
        console.log("MayanRouter:", addresses.mayanRouter);

        // Configure Router
        Router router = Router(addresses.router);
        router.setRouter(Route.MAYAN, addresses.mayanRouter);
        console.log("MayanRouter configured in Router");

        vm.stopBroadcast();

        // ========== Verify Deployment ==========
        console.log("\n========== Verifying Deployment ==========");
        _verifyDeployment(addresses);

        // ========== Print Summary ==========
        _printSummary(addresses);

        return addresses;
    }

    function _verifyDeployment(
        DeploymentAddresses memory addresses
    ) internal view {
        Router router = Router(addresses.router);
        Vault vault = Vault(payable(addresses.vaultProxy));

        // Verify Router
        require(
            router.hasRole(router.DEFAULT_ADMIN_ROLE(), addresses.admin),
            "Router: Admin role not granted"
        );
        require(
            router.routers(Route.MAYAN) == addresses.mayanRouter,
            "Router: MayanRouter not configured"
        );

        // Verify Vault
        require(
            vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), addresses.admin),
            "Vault: Admin role not granted"
        );
        require(
            address(vault.router()) == addresses.router,
            "Vault: Router not set"
        );

        console.log("All verifications passed");
    }

    function _printSummary(
        DeploymentAddresses memory addresses
    ) internal pure {
        console.log("\n========================================");
        console.log("DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("Admin:", addresses.admin);
        console.log("----------------------------------------");
        console.log("Router:", addresses.router);
        console.log("----------------------------------------");
        console.log("Vault Proxy:", addresses.vaultProxy);
        console.log("Vault Implementation:", addresses.vaultImplementation);
        console.log("----------------------------------------");
        console.log("MayanRouter:", addresses.mayanRouter);
        console.log("========================================\n");
    }
}
