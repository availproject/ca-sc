// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Vault} from "../src/Vault.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address);
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address);
}

/// @title DeployAll
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Script to deploy complete system via createX deterministic CREATE2
contract DeployAll is Script {
    ICreateX public constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    struct DeploymentAddresses {
        address vaultProxy;
        address mayanRouter;
        address admin;
    }

    function run() external returns (DeploymentAddresses memory addresses) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address admin = vm.envAddress("ADMIN_ADDRESS");

        addresses.admin = admin;

        vm.startBroadcast(deployerPrivateKey);
        address deployer = vm.addr(deployerPrivateKey);

        // Base version used to derive all CREATE2 salts deterministically
        string memory baseVersion = "1.0.8";

        console.log("\n========== Deploying Vault (createX) ==========");
        bytes32 vaultSalt = keccak256(abi.encodePacked("nexus-mayan-vault-", baseVersion));
        bytes32 proxySalt = keccak256(abi.encodePacked(vaultSalt, "proxy"));

        bytes memory vaultInitCode = type(Vault).creationCode;
        bytes32 vaultInitCodeHash = keccak256(vaultInitCode);
        address expectedImpl = CREATEX.computeCreate2Address(keccak256(abi.encode(vaultSalt)), vaultInitCodeHash);
        console.log("Expected implementation:", expectedImpl);

        bytes memory initData = abi.encodeWithSelector(Vault.initialize.selector, deployer);
        bytes memory proxyInitCode =
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(expectedImpl, initData));
        bytes32 proxyInitCodeHash = keccak256(proxyInitCode);
        address expectedProxy = CREATEX.computeCreate2Address(keccak256(abi.encode(proxySalt)), proxyInitCodeHash);
        console.log("Expected proxy:", expectedProxy);

        address implementation = CREATEX.deployCreate2(vaultSalt, vaultInitCode);
        console.log("Implementation:", implementation);
        require(implementation == expectedImpl, "Implementation address mismatch");

        addresses.vaultProxy = CREATEX.deployCreate2(proxySalt, proxyInitCode);
        console.log("Vault proxy:", addresses.vaultProxy);
        require(addresses.vaultProxy == expectedProxy, "Proxy address mismatch");

        Vault vault = Vault(payable(addresses.vaultProxy));

        // If admin is different, transfer control
        if (addresses.admin != deployer) {
            vault.grantRole(vault.DEFAULT_ADMIN_ROLE(), addresses.admin);
            vault.renounceRole(vault.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred Vault admin rights to:", addresses.admin);
        }

        console.log("\n========== Deploying MayanRouter (createX) ==========");
        bytes32 mayanSalt = keccak256(abi.encodePacked("nexus-mayan-mayanrouter-", baseVersion));
        bytes32 mayanProxySalt = keccak256(abi.encodePacked(mayanSalt, "proxy"));

        bytes memory mayanInitCode = type(MayanRouter).creationCode;
        bytes32 mayanInitCodeHash = keccak256(mayanInitCode);
        address expectedMayanImpl = CREATEX.computeCreate2Address(keccak256(abi.encode(mayanSalt)), mayanInitCodeHash);
        console.log("Expected MayanRouter implementation:", expectedMayanImpl);

        bytes memory mayanRouterInitData = abi.encodeWithSelector(MayanRouter.initialize.selector, deployer);
        bytes memory mayanProxyInitCode =
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(expectedMayanImpl, mayanRouterInitData));
        bytes32 mayanProxyInitCodeHash = keccak256(mayanProxyInitCode);
        address expectedMayanProxy =
            CREATEX.computeCreate2Address(keccak256(abi.encode(mayanProxySalt)), mayanProxyInitCodeHash);
        console.log("Expected MayanRouter proxy:", expectedMayanProxy);

        address mayanImplementation = CREATEX.deployCreate2(mayanSalt, mayanInitCode);
        console.log("MayanRouter implementation:", mayanImplementation);
        require(mayanImplementation == expectedMayanImpl, "MayanRouter implementation address mismatch");

        addresses.mayanRouter = CREATEX.deployCreate2(mayanProxySalt, mayanProxyInitCode);
        console.log("MayanRouter proxy:", addresses.mayanRouter);
        require(addresses.mayanRouter == expectedMayanProxy, "MayanRouter proxy address mismatch");

        vault.setRouter(addresses.mayanRouter);
        console.log("MayanRouter set as Vault router");

        MayanRouter mayanRouter = MayanRouter(addresses.mayanRouter);
        mayanRouter.grantRole(mayanRouter.VAULT_ROLE(), addresses.vaultProxy);
        console.log("Vault granted MayanRouter VAULT_ROLE");

        if (addresses.admin != deployer) {
            mayanRouter.transferOwnership(addresses.admin);
            mayanRouter.grantRole(mayanRouter.DEFAULT_ADMIN_ROLE(), addresses.admin);
            mayanRouter.grantRole(mayanRouter.UPGRADER_ROLE(), addresses.admin);
            mayanRouter.renounceRole(mayanRouter.UPGRADER_ROLE(), deployer);
            mayanRouter.renounceRole(mayanRouter.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred MayanRouter ownership and admin rights to:", addresses.admin);
        }

        vm.stopBroadcast();

        console.log("\n========== Verifying Deployment ==========");
        _verifyDeployment(addresses);

        _printSummary(addresses);

        return addresses;
    }

    function _verifyDeployment(DeploymentAddresses memory addresses) internal view {
        Vault vault = Vault(payable(addresses.vaultProxy));

        require(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), addresses.admin), "Vault: Admin role not granted");
        require(address(vault.router()) == addresses.mayanRouter, "Vault: MayanRouter not set");
        require(
            MayanRouter(addresses.mayanRouter)
                .hasRole(MayanRouter(addresses.mayanRouter).VAULT_ROLE(), addresses.vaultProxy),
            "MayanRouter: Vault role not granted"
        );

        console.log("All verifications passed");
    }

    function _printSummary(DeploymentAddresses memory addresses) internal pure {
        console.log("\n========================================");
        console.log("DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("Admin:", addresses.admin);
        console.log("----------------------------------------");
        console.log("Vault Proxy:", addresses.vaultProxy);
        console.log("----------------------------------------");
        console.log("MayanRouter:", addresses.mayanRouter);
        console.log("========================================\n");
    }
}
