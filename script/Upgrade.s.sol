// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Vault} from "../src/Vault.sol";

contract UpgradeVault is Script {
    function run() external returns (address newImplementation) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address proxyAddress = vm.envAddress("PROXY_ADDRESS");

        vm.startBroadcast(deployerPrivateKey);

        Vault newVaultImpl = new Vault();
        newImplementation = address(newVaultImpl);

        Vault proxy = Vault(payable(proxyAddress));
        proxy.upgradeToAndCall(newImplementation, "");

        vm.stopBroadcast();

        console.log("Proxy Address:", proxyAddress);
        console.log("New Implementation:", newImplementation);

        return newImplementation;
    }
}
