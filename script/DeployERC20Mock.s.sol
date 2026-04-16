// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {ERC20Mock} from "../src/mocks/ERC20Mock.sol";

contract DeployERC20Mock is Script {
    function run() external returns (address token) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        ERC20Mock mockToken = new ERC20Mock();
        token = address(mockToken);

        vm.stopBroadcast();

        console.log("ERC20Mock deployed at:", token);
        console.log("Name: Mock Token");
        console.log("Symbol: MOCK");

        return token;
    }
}
