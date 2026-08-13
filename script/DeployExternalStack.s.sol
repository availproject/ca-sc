// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {Executor} from "../src/Executor.sol";
import {Vault} from "../src/Vault.sol";

/// @title DeployExternalStack
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Freshly deploys and configures a Vault implementation/proxy and its immutable
/// Executor.
contract DeployExternalStack is Script {
    struct DeploymentAddresses {
        address vaultImplementation;
        address vaultProxy;
        address executor;
    }

    /// @notice Deploys a completely fresh external-intent stack.
    /// @dev Required environment variables:
    /// - PRIVATE_KEY: broadcaster key; its address becomes the Vault admin
    /// - MPC_ADDRESS (or MPC): settlement verifier address
    /// Optional environment variables:
    /// - EXECUTOR_OWNER: owner of the Executor; defaults to the broadcaster
    function run() external returns (DeploymentAddresses memory addresses) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address mpc = _getMpc();
        address executorOwner = vm.envOr("EXECUTOR_OWNER", deployer);

        require(mpc != address(0), "DeployExternalStack: MPC zero address");
        require(executorOwner != address(0), "DeployExternalStack: Executor owner zero address");

        vm.startBroadcast(deployerPrivateKey);

        Vault vaultImplementation = new Vault();
        ERC1967Proxy vaultProxy =
            new ERC1967Proxy(address(vaultImplementation), abi.encodeCall(Vault.initialize, (deployer, mpc)));
        Vault vault = Vault(payable(address(vaultProxy)));

        Executor executor = new Executor(address(vault), executorOwner);

        vault.setExecutor(address(executor));

        vm.stopBroadcast();

        addresses = DeploymentAddresses({
            vaultImplementation: address(vaultImplementation), vaultProxy: address(vault), executor: address(executor)
        });

        _verify(addresses, deployer, mpc, executorOwner);
        _printSummary(addresses, deployer, mpc, executorOwner);
    }

    function _verify(DeploymentAddresses memory addresses, address admin, address mpc, address executorOwner)
        internal
        view
    {
        Vault vault = Vault(payable(addresses.vaultProxy));
        Executor executor = Executor(payable(addresses.executor));

        require(addresses.vaultImplementation.code.length > 0, "DeployExternalStack: Vault impl missing");
        require(addresses.vaultProxy.code.length > 0, "DeployExternalStack: Vault proxy missing");
        require(addresses.executor.code.length > 0, "DeployExternalStack: Executor missing");

        require(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin), "DeployExternalStack: admin missing");
        require(vault.hasRole(keccak256("SETTLEMENT_VERIFIER_ROLE"), mpc), "DeployExternalStack: verifier missing");
        require(vault.executor() == addresses.executor, "DeployExternalStack: Vault executor mismatch");
        require(executor.vault() == addresses.vaultProxy, "DeployExternalStack: Executor vault mismatch");
        require(executor.owner() == executorOwner, "DeployExternalStack: Executor owner mismatch");
    }

    function _printSummary(DeploymentAddresses memory addresses, address admin, address mpc, address executorOwner)
        internal
        pure
    {
        console.log("Chain deployment complete");
        console.log("Admin:", admin);
        console.log("MPC:", mpc);
        console.log("Executor owner:", executorOwner);
        console.log("Vault implementation:", addresses.vaultImplementation);
        console.log("Vault proxy:", addresses.vaultProxy);
        console.log("Executor:", addresses.executor);
    }

    function _getMpc() internal view returns (address) {
        try vm.envAddress("MPC_ADDRESS") returns (address mpcAddress) {
            return mpcAddress;
        } catch {
            return vm.envAddress("MPC");
        }
    }
}
