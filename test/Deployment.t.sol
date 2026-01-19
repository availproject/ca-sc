// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {DeployAll} from "../script/DeployAll.s.sol";
import {Router} from "../src/Router.sol";
import {Vault} from "../src/Vault.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {Route} from "../src/types.sol";

contract DeploymentTest is Test {
    DeployAll deployScript;
    address admin;

    function setUp() public {
        admin = makeAddr("admin");
        vm.setEnv("PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
        vm.setEnv("ADMIN_ADDRESS", vm.toString(admin));
        
        deployScript = new DeployAll();
    }

    function test_DeployAll() public {
        DeployAll.DeploymentAddresses memory addresses = deployScript.run();

        assertTrue(addresses.router != address(0), "Router is zero");
        assertTrue(addresses.vaultProxy != address(0), "Vault proxy is zero");
        assertTrue(addresses.mayanRouter != address(0), "MayanRouter is zero");

        Router router = Router(addresses.router);
        assertTrue(
            router.hasRole(router.DEFAULT_ADMIN_ROLE(), admin),
            "Router admin not set"
        );
        assertEq(
            router.routers(Route.MAYAN),
            addresses.mayanRouter,
            "MayanRouter not configured"
        );

        Vault vault = Vault(payable(addresses.vaultProxy));
        assertTrue(
            vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin),
            "Vault admin not set"
        );
        assertEq(
            address(vault.router()),
            addresses.router,
            "Router not set in Vault"
        );

        MayanRouter mayanRouter = MayanRouter(addresses.mayanRouter);
        assertEq(
            mayanRouter.owner(),
            admin,
            "MayanRouter owner not set"
        );
    }
}
