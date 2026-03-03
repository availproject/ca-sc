// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Vault} from "../contracts/Vault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title ICreateX
 * @notice Interface for the CreateX factory for deterministic CREATE2 deployments
 * @dev CreateX is deployed at 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed on all EVM chains
 */
interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address);
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address);
}

/**
 * @title DeployVaultCreate2
 * @notice Deploys Vault with UUPS proxy pattern using CREATE2 for deterministic addresses
 * @dev Uses CreateX factory for cross-chain deterministic deployments
 *      Factory: 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed
 * 
 * Usage: 
 *   forge script script/DeployVaultCreate2.s.sol --rpc-url $RPC_URL --broadcast --json
 * 
 * Environment variables:
 *   - PRIVATE_KEY: Deployer private key
 *   - SALT: Optional salt for deterministic deployment (hex string)
 */
contract DeployVaultCreate2 is Script {
    /// @notice CreateX factory address (deployed on all EVM chains)
    ICreateX public constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);
    
    /// @notice Default salt - can be overridden via SALT env variable
    bytes32 public constant DEFAULT_SALT = keccak256("");

    function run() external returns (address proxy) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        
        // Get salt from env or use default
        bytes32 salt = _getSalt();
        // Compute salt for proxy (implementation salt + "proxy" to ensure unique)
        bytes32 proxySalt = keccak256(abi.encodePacked(salt, "nexusv2proxy"));

        console.log("Deployer:", deployer);
        console.log("Salt (impl):", vm.toString(salt));
        console.log("Salt (proxy):", vm.toString(proxySalt));

        // 1. Prepare Vault implementation init code
        bytes memory vaultInitCode = type(Vault).creationCode;
        bytes32 vaultInitCodeHash = keccak256(vaultInitCode);

        // Compute expected implementation address
        address expectedImpl = CREATEX.computeCreate2Address(salt, vaultInitCodeHash);
        console.log("Expected implementation:", expectedImpl);

        // 2. Prepare proxy initialization data
        bytes memory initData = abi.encodeWithSelector(
            Vault.initialize.selector,
            deployer // admin
        );

        // 3. Prepare ERC1967Proxy init code
        bytes memory proxyInitCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(expectedImpl, initData)
        );
        bytes32 proxyInitCodeHash = keccak256(proxyInitCode);

        // Compute expected proxy address
        address expectedProxy = CREATEX.computeCreate2Address(proxySalt, proxyInitCodeHash);
        console.log("Expected proxy:", expectedProxy);

        vm.startBroadcast(deployerPrivateKey);

        // 4. Deploy Vault implementation using CREATE2
        address implementation = CREATEX.deployCreate2(salt, vaultInitCode);
        console.log("Implementation deployed at:", implementation);
        require(implementation == expectedImpl, "Implementation address mismatch");

        // 5. Deploy ERC1967Proxy using CREATE2
        proxy = CREATEX.deployCreate2(proxySalt, proxyInitCode);
        console.log("Proxy deployed at:", proxy);
        require(proxy == expectedProxy, "Proxy address mismatch");

        vm.stopBroadcast();

        // Output deployment summary
        console.log("\n=== Deployment Summary ===");
        console.log("Implementation:", implementation);
        console.log("Proxy:", proxy);
        console.log("Admin:", deployer);
        console.log("Chain ID:", block.chainid);
        console.log("===========================");
    }

    /**
     * @notice Preview expected deployment addresses without deploying
     * @dev Useful for verifying addresses before actual deployment
     * Usage: 
     *   forge script script/DeployVaultCreate2.s.sol --sig 'previewAddresses()' --rpc-url $RPC_URL
     */
    function previewAddresses() external view returns (address impl, address proxy) {
        bytes32 salt = _getSalt();
        bytes32 proxySalt = keccak256(abi.encodePacked(salt, "proxy"));

        // Compute implementation address
        impl = CREATEX.computeCreate2Address(
            salt,
            keccak256(type(Vault).creationCode)
        );

        // Prepare proxy init code for address computation
        bytes memory initData = abi.encodeWithSelector(
            Vault.initialize.selector,
            msg.sender
        );
        bytes memory proxyInitCode = abi.encodePacked(
            type(ERC1967Proxy).creationCode,
            abi.encode(impl, initData)
        );
        
        proxy = CREATEX.computeCreate2Address(
            proxySalt,
            keccak256(proxyInitCode)
        );

        console.log("Expected Implementation:", impl);
        console.log("Expected Proxy:", proxy);
        console.log("Chain ID:", block.chainid);
    }

    /**
     * @notice Internal helper to get salt from environment or use default
     */
    function _getSalt() internal view returns (bytes32) {
        try vm.envBytes32("SALT") returns (bytes32 envSalt) {
            return envSalt;
        } catch {
            return DEFAULT_SALT;
        }
    }
}
