// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Vault} from "../src/Vault.sol";
import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

/// @title DeployVault
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy the Vault contract with UUPS proxy
contract DeployVault is Script {
    function run() external returns (address proxy) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");
        address routerAddress = vm.envAddress("ROUTER_ADDRESS");

        require(routerAddress != address(0), "Router address cannot be zero");

        vm.startBroadcast(deployerPrivateKey);
        address deployer = vm.addr(deployerPrivateKey);

        proxy = Upgrades.deployUUPSProxy(
            "Vault.sol",
            abi.encodeCall(Vault.initialize, (deployer))
        );
        console.log("Vault proxy deployed at:", proxy);
        console.log("Admin address:", admin);

        Vault vault = Vault(payable(proxy));
        vault.setRouter(routerAddress);
        console.log("Router set to:", routerAddress);

        if (admin != deployer) {
            vault.grantRole(vault.DEFAULT_ADMIN_ROLE(), admin);
            vault.renounceRole(vault.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred Vault admin rights to:", admin);
        }

        vm.stopBroadcast();

        require(
            vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin),
            "Admin role not granted"
        );
        require(
            address(vault.router()) == routerAddress,
            "Router not set correctly"
        );
        console.log("Deployment verified successfully");

        return proxy;
    }
}
