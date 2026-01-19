// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Vault} from "../../src/Vault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployVault
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy the Vault contract with UUPS proxy
contract DeployVault is Script {
    function run() external returns (address proxy, address implementation) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");
        address routerAddress = vm.envAddress("ROUTER_ADDRESS");

        require(routerAddress != address(0), "Router address cannot be zero");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy implementation
        implementation = address(new Vault());
        console.log("Vault implementation deployed at:", implementation);

        // Encode initializer
        bytes memory initData = abi.encodeWithSelector(
            Vault.initialize.selector,
            admin
        );

        // Deploy proxy
        proxy = address(new ERC1967Proxy(implementation, initData));
        console.log("Vault proxy deployed at:", proxy);
        console.log("Admin address:", admin);

        // Set router in Vault
        Vault vault = Vault(payable(proxy));
        vault.setRouter(routerAddress);
        console.log("Router set to:", routerAddress);

        vm.stopBroadcast();

        // Verify deployment
        require(
            vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin),
            "Admin role not granted"
        );
        require(
            address(vault.router()) == routerAddress,
            "Router not set correctly"
        );
        console.log("Deployment verified successfully");

        return (proxy, implementation);
    }
}
