// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Vault} from "../src/Vault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployVault is Script {
    function run() external returns (address proxy, address implementation) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envOr("ADMIN_ADDRESS", vm.addr(deployerPrivateKey));

        vm.startBroadcast(deployerPrivateKey);

        Vault vaultImpl = new Vault();
        implementation = address(vaultImpl);

        bytes memory initData = abi.encodeCall(Vault.initialize, (admin));
        ERC1967Proxy vaultProxy = new ERC1967Proxy(implementation, initData);
        proxy = address(vaultProxy);

        vm.stopBroadcast();

        console.log("Vault Implementation:", implementation);
        console.log("Vault Proxy:", proxy);
        console.log("Admin:", admin);

        return (proxy, implementation);
    }
}

contract DeployVaultImplementation is Script {
    function run() external returns (address implementation) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        Vault vaultImpl = new Vault();
        implementation = address(vaultImpl);

        vm.stopBroadcast();

        console.log("Vault Implementation:", implementation);

        return implementation;
    }
}
