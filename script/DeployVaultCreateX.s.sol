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
    bytes32 public constant DEFAULT_SALT = keccak256("nexus-vault-001");

    function run() external returns (address proxy) {
        address admin = _getAdmin();
        vm.startBroadcast();
        bytes32 salt = _getSalt();
        bytes32 proxySalt = keccak256(abi.encodePacked(salt, "proxy"));

        console.log("Admin:", admin);
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
}
