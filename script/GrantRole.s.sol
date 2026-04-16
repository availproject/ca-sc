// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Vault} from "../contracts/Vault.sol";

interface IVault {
    function hasRole(bytes32 role, address account) external view returns (bool);
    function grantRole(bytes32 role, address account) external;
    function DEFAULT_ADMIN_ROLE() external view returns (bytes32);
}

contract GrantRole is Script {
    bytes32 public constant SETTLEMENT_VERIFIER_ROLE = keccak256("SETTLEMENT_VERIFIER_ROLE");

    function run(address vault, address[] calldata addresses) external {
        _grantRoles(vault, addresses);
    }

    function run(address vault, string calldata addressesStr) external {
        address[] memory addresses = _parseAddresses(addressesStr);
        _grantRoles(vault, addresses);
    }

    function _grantRoles(address vault, address[] memory addresses) internal {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        IVault vaultContract = IVault(vault);

        require(vaultContract.hasRole(vaultContract.DEFAULT_ADMIN_ROLE(), deployer), "Caller does not have admin role");

        uint256 successCount = 0;
        uint256 skipCount = 0;

        for (uint256 i = 0; i < addresses.length; i++) {
            address addr = addresses[i];

            if (vaultContract.hasRole(SETTLEMENT_VERIFIER_ROLE, addr)) {
                console.log("[%s/%s] Already has role:", i + 1, addresses.length, addr);
                skipCount++;
                continue;
            }

            console.log("[%s/%s] Granting role to:", i + 1, addresses.length, addr);
            vaultContract.grantRole(SETTLEMENT_VERIFIER_ROLE, addr);
            successCount++;
        }

        vm.stopBroadcast();

        console.log("\n=== SUMMARY ===");
        console.log("Total processed:", addresses.length);
        console.log("Granted:", successCount);
        console.log("Skipped (already had role):", skipCount);
    }

    function _parseAddresses(string memory str) internal pure returns (address[] memory) {
        bytes memory strBytes = bytes(str);
        uint256 count = 1;
        for (uint256 i = 0; i < strBytes.length; i++) {
            if (strBytes[i] == ",") count++;
        }

        address[] memory addresses = new address[](count);
        uint256 current = 0;
        uint256 start = 0;

        for (uint256 i = 0; i <= strBytes.length; i++) {
            if (i == strBytes.length || strBytes[i] == ",") {
                bytes memory addrBytes = new bytes(42);
                for (uint256 j = 0; j < 42 && start + j < strBytes.length; j++) {
                    addrBytes[j] = strBytes[start + j];
                }
                addresses[current] = _parseAddress(string(addrBytes));
                current++;
                start = i + 1;
            }
        }

        return addresses;
    }

    function _parseAddress(string memory str) internal pure returns (address) {
        bytes memory strBytes = bytes(str);
        require(strBytes.length == 42, "Invalid address length");
        require(strBytes[0] == "0" && strBytes[1] == "x", "Invalid address prefix");

        uint160 addr = 0;
        for (uint256 i = 2; i < 42; i++) {
            addr *= 16;
            uint8 b = uint8(strBytes[i]);
            if (b >= 48 && b <= 57) {
                addr += b - 48;
            } else if (b >= 65 && b <= 70) {
                addr += b - 55;
            } else if (b >= 97 && b <= 102) {
                addr += b - 87;
            } else {
                revert("Invalid hex character");
            }
        }
        return address(addr);
    }
}
