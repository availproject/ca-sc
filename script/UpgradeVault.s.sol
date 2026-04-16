// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Vault} from "../contracts/Vault.sol";

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address);
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address);
}

interface IVault {
    function hasRole(bytes32 role, address account) external view returns (bool);
    function upgradeToAndCall(address newImplementation, bytes memory data) external;
}

contract UpgradeVault is Script {
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x0000000000000000000000000000000000000000000000000000000000000000;
    ICreateX public constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    function run(address proxyAddress, bytes32 salt) external {
        _upgrade(proxyAddress, salt);
    }

    function run(address proxyAddress) external {
        bytes32 salt = keccak256(abi.encodePacked("upgrade", block.timestamp, proxyAddress));
        _upgrade(proxyAddress, salt);
    }

    function run() external {
        address proxyAddress = vm.envAddress("PROXY_ADDRESS");
        bytes32 salt;
        try vm.envBytes32("UPGRADE_SALT") returns (bytes32 envSalt) {
            salt = envSalt;
        } catch {
            salt = keccak256(abi.encodePacked("upgrade", block.timestamp, proxyAddress));
        }
        _upgrade(proxyAddress, salt);
    }

    function _upgrade(address proxyAddress, bytes32 salt) internal {
        address deployer;

        // Try to use PRIVATE_KEY from env, otherwise use AWS KMS (via --aws flag)
        try vm.envUint("PRIVATE_KEY") returns (uint256 deployerPrivateKey) {
            deployer = vm.addr(deployerPrivateKey);
            vm.startBroadcast(deployerPrivateKey);
        } catch {
            // AWS mode: use vm.startBroadcast() without key
            deployer = msg.sender;
            vm.startBroadcast();
        }

        console.log("Deployer:", deployer);
        console.log("Proxy:", proxyAddress);
        console.log("Salt:", vm.toString(salt));

        address currentImpl = getImplementation(proxyAddress);
        console.log("Current Implementation:", currentImpl);

        bytes memory vaultInitCode = type(Vault).creationCode;
        bytes32 vaultInitCodeHash = keccak256(vaultInitCode);
        address expectedImpl = CREATEX.computeCreate2Address(salt, vaultInitCodeHash);
        console.log("Expected New Implementation:", expectedImpl);

        IVault proxy = IVault(proxyAddress);
        bool hasUpgraderRole = proxy.hasRole(UPGRADER_ROLE, deployer);
        bool hasAdminRole = proxy.hasRole(DEFAULT_ADMIN_ROLE, deployer);
        require(hasUpgraderRole || hasAdminRole, "Caller does not have UPGRADER_ROLE or ADMIN_ROLE");

        address newImplementation = CREATEX.deployCreate2(salt, vaultInitCode);
        console.log("New Implementation:", newImplementation);
        require(newImplementation == expectedImpl, "Implementation address mismatch");

        proxy.upgradeToAndCall(newImplementation, "");
        console.log("Proxy upgraded");

        vm.stopBroadcast();

        address verifiedImpl = getImplementation(proxyAddress);
        console.log("\n=== UPGRADE COMPLETE ===");
        console.log("Old Implementation:", currentImpl);
        console.log("New Implementation:", verifiedImpl);
        require(verifiedImpl == newImplementation, "Upgrade verification failed");
        console.log("Upgrade verified");
    }

    function preview(address proxyAddress, bytes32 salt) external view returns (address newImpl) {
        console.log("Proxy:", proxyAddress);
        console.log("Salt:", vm.toString(salt));

        newImpl = CREATEX.computeCreate2Address(salt, keccak256(type(Vault).creationCode));
        console.log("Expected New Implementation:", newImpl);

        address currentImpl = getImplementation(proxyAddress);
        console.log("Current Implementation:", currentImpl);
    }

    function getImplementation(address proxy) internal view returns (address) {
        bytes32 implSlot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 implBytes = vm.load(proxy, implSlot);
        return address(uint160(uint256(implBytes)));
    }
}
