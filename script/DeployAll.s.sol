// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Router} from "../src/Router.sol";
import {Vault} from "../src/Vault.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {Route} from "../src/types.sol";
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
        address router;
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

        console.log("\n========== Deploying Router (createX) ==========");
        bytes32 routerSalt = keccak256(abi.encodePacked("nexus-mayan-router-1.0.3"));
        bytes memory routerInitCode = abi.encodePacked(type(Router).creationCode, abi.encode(deployer));
        addresses.router = CREATEX.deployCreate2(routerSalt, routerInitCode);
        console.log("Router deployed at:", addresses.router);

        console.log("\n========== Deploying Vault (createX) ==========");
        bytes32 vaultSalt = keccak256(abi.encodePacked("nexus-mayan-vault-1.0.3"));
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
        vault.setRouter(addresses.router);
        console.log("Router set in Vault");

        // If admin is different, transfer control
        if (addresses.admin != deployer) {
            vault.grantRole(vault.DEFAULT_ADMIN_ROLE(), addresses.admin);
            vault.renounceRole(vault.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred Vault admin rights to:", addresses.admin);
        }

        console.log("\n========== Deploying MayanRouter (createX) ==========");
        bytes32 mayanSalt = keccak256(abi.encodePacked("nexus-mayan-mayanrouter-1.0.3"));
        bytes memory mayanInitCode = abi.encodePacked(type(MayanRouter).creationCode, abi.encode(deployer));
        addresses.mayanRouter = CREATEX.deployCreate2(mayanSalt, mayanInitCode);
        console.log("MayanRouter:", addresses.mayanRouter);

        Router router = Router(addresses.router);
        router.setRouter(Route.MAYAN, addresses.mayanRouter);
        console.log("MayanRouter configured in Router");

        MayanRouter mayanRouter = MayanRouter(addresses.mayanRouter);
        if (addresses.admin != deployer) {
            mayanRouter.transferOwnership(addresses.admin);
            console.log("Transferred MayanRouter ownership to:", addresses.admin);
        }

        // Transfer Router admin rights if needed
        if (addresses.admin != deployer) {
            router.grantRole(router.DEFAULT_ADMIN_ROLE(), addresses.admin);
            router.renounceRole(router.DEFAULT_ADMIN_ROLE(), deployer);
            console.log("Transferred Router admin rights to:", addresses.admin);
        }

        vm.stopBroadcast();

        console.log("\n========== Verifying Deployment ==========");
        _verifyDeployment(addresses);

        _printSummary(addresses);

        return addresses;
    }

    function _verifyDeployment(DeploymentAddresses memory addresses) internal view {
        Router router = Router(addresses.router);
        Vault vault = Vault(payable(addresses.vaultProxy));

        require(router.hasRole(router.DEFAULT_ADMIN_ROLE(), addresses.admin), "Router: Admin role not granted");
        require(router.routers(Route.MAYAN) == addresses.mayanRouter, "Router: MayanRouter not configured");

        require(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), addresses.admin), "Vault: Admin role not granted");
        require(address(vault.router()) == addresses.router, "Vault: Router not set");

        console.log("All verifications passed");
    }

    function _printSummary(DeploymentAddresses memory addresses) internal pure {
        console.log("\n========================================");
        console.log("DEPLOYMENT SUMMARY");
        console.log("========================================");
        console.log("Admin:", addresses.admin);
        console.log("----------------------------------------");
        console.log("Router:", addresses.router);
        console.log("----------------------------------------");
        console.log("Vault Proxy:", addresses.vaultProxy);
        console.log("----------------------------------------");
        console.log("MayanRouter:", addresses.mayanRouter);
        console.log("========================================\n");
    }
}
