// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Vault} from "../contracts/Vault.sol";
import {
    ERC1967Proxy
} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @notice Deploys Vault with UUPS proxy pattern
/// @dev Usage: forge script script/DeployVault.s.sol --rpc-url $RPC_URL --broadcast --json
contract DeployVault is Script {
    function run() external returns (address proxy) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // 1. Deploy implementation
        Vault implementation = new Vault();
        console.log("Implementation:", address(implementation));

        // 2. Deploy proxy with initialize calldata
        bytes memory initData = abi.encodeWithSelector(
            Vault.initialize.selector,
            deployer // admin
        );

        ERC1967Proxy proxyContract = new ERC1967Proxy(
            address(implementation),
            initData
        );
        proxy = address(proxyContract);
        console.log("Proxy:", proxy);

        vm.stopBroadcast();

        // Output JSON for parsing
        console.log("DEPLOYED_ADDRESS:", proxy);
    }
}
