// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Vault} from "../contracts/Vault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address);
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address);
}

contract DeployVault is Script {
    ICreateX public constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);
    bytes32 public constant DEFAULT_SALT = keccak256("nexus-vault-1.0.5");
    bytes32 private constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    function run() external returns (address proxy) {
        address admin = _getAdmin();
        address finalAdmin = _getFinalAdmin(admin);
        vm.startBroadcast();
        bytes32 salt = _getSalt();
        bytes32 proxySalt = keccak256(abi.encodePacked(salt, "proxy"));

        console.log("Admin:", admin);
        console.log("Final Admin:", finalAdmin);
        console.log("Salt (impl):", vm.toString(salt));
        console.log("Salt (proxy):", vm.toString(proxySalt));

        bytes memory vaultInitCode = type(Vault).creationCode;
        bytes32 vaultInitCodeHash = keccak256(vaultInitCode);
        address expectedImpl = CREATEX.computeCreate2Address(keccak256(abi.encode(salt)), vaultInitCodeHash);
        console.log("Expected implementation:", expectedImpl);

        bytes memory initData = abi.encodeWithSelector(Vault.initialize.selector, admin);
        bytes memory proxyInitCode =
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(expectedImpl, initData));
        bytes32 proxyInitCodeHash = keccak256(proxyInitCode);
        address expectedProxy = CREATEX.computeCreate2Address(keccak256(abi.encode(proxySalt)), proxyInitCodeHash);
        console.log("Expected proxy:", expectedProxy);

        address implementation = CREATEX.deployCreate2(salt, vaultInitCode);
        console.log("Implementation:", implementation);
        require(implementation == expectedImpl, "Implementation address mismatch");

        proxy = CREATEX.deployCreate2(proxySalt, proxyInitCode);
        console.log("Proxy:", proxy);
        require(proxy == expectedProxy, "Proxy address mismatch");

        vm.stopBroadcast();

        console.log("DEPLOYED_ADDRESS:", proxy);

        // Transfer ownership to finalAdmin if specified and different from admin
        if (finalAdmin != address(0) && finalAdmin != admin) {
            _transferOwnership(proxy, admin, finalAdmin);
        }
    }

    function _transferOwnership(address proxy, address admin, address finalAdmin) internal {
        uint256 adminPrivateKey = _getAdminPrivateKey();
        require(adminPrivateKey != 0, "DeployVault: ADMIN_PRIVATE_KEY required for ownership transfer");
        address upgraderWallet = _getUpgraderWallet(admin);

        vm.startBroadcast(adminPrivateKey);

        Vault vault = Vault(proxy);

        // Grant DEFAULT_ADMIN_ROLE to finalAdmin
        vault.grantRole(vault.DEFAULT_ADMIN_ROLE(), finalAdmin);
        console.log("Granted DEFAULT_ADMIN_ROLE to:", finalAdmin);

        // Grant UPGRADER_ROLE to upgrader wallet (defaults to admin if not set)
        vault.grantRole(UPGRADER_ROLE, upgraderWallet);
        console.log("Granted UPGRADER_ROLE to:", upgraderWallet);

        // Get the deployer address (current admin)
        address deployer = vm.addr(adminPrivateKey);

        // Renounce roles from deployer
        vault.renounceRole(vault.DEFAULT_ADMIN_ROLE(), deployer);
        vault.renounceRole(UPGRADER_ROLE, deployer);
        console.log("Renounced roles from deployer:", deployer);

        vm.stopBroadcast();

        console.log("Ownership transferred to finalAdmin:", finalAdmin);
    }

    function preview(address admin) external view returns (address impl, address proxy) {
        bytes32 salt = _getSalt();
        bytes32 proxySalt = keccak256(abi.encodePacked(salt, "proxy"));

        impl = CREATEX.computeCreate2Address(salt, keccak256(type(Vault).creationCode));

        bytes memory initData = abi.encodeWithSelector(Vault.initialize.selector, admin);
        bytes memory proxyInitCode = abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(impl, initData));
        proxy = CREATEX.computeCreate2Address(proxySalt, keccak256(proxyInitCode));

        console.log("Admin:", admin);
        console.log("Expected Implementation:", impl);
        console.log("Expected Proxy:", proxy);
    }

    function _getSalt() internal view returns (bytes32) {
        try vm.envBytes32("SALT") returns (bytes32 envSalt) {
            return envSalt;
        } catch {
            return DEFAULT_SALT;
        }
    }

    function _getAdmin() internal view returns (address) {
        try vm.envAddress("ADMIN") returns (address envAdmin) {
            return envAdmin;
        } catch {
            return msg.sender;
        }
    }

    function _getFinalAdmin(address admin) internal view returns (address) {
        try vm.envAddress("FINAL_ADMIN") returns (address envFinalAdmin) {
            return envFinalAdmin;
        } catch {
            return admin;
        }
    }

    function _getAdminPrivateKey() internal view returns (uint256) {
        try vm.envUint("ADMIN_PRIVATE_KEY") returns (uint256 envPrivateKey) {
            return envPrivateKey;
        } catch {
            return 0;
        }
    }

    function _getUpgraderWallet(address admin) internal view returns (address) {
        try vm.envAddress("UPGRADER_WALLET") returns (address envUpgrader) {
            return envUpgrader;
        } catch {
            return admin;
        }
    }
}
