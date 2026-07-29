// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {Executor} from "../src/Executor.sol";
import {Router} from "../src/Router.sol";
import {Vault} from "../src/Vault.sol";

/// @title DeployExternalStack
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Freshly deploys and configures a Vault implementation/proxy and its immutable
/// Executor/Router pair.
/// @dev Executor and Router contain each other's immutable addresses. The Router address is
/// predicted from the broadcaster's nonce before either member of the pair is deployed.
/// Do not submit another transaction from the deployer while this deployment is in progress.
contract DeployExternalStack is Script {
    struct DeploymentAddresses {
        address vaultImplementation;
        address vaultProxy;
        address executor;
        address router;
    }

    /// @notice Deploys a completely fresh external-intent stack.
    /// @dev Required environment variables:
    /// - PRIVATE_KEY: broadcaster key; its address becomes the Vault admin
    /// - MPC_ADDRESS (or MPC): settlement verifier address
    /// - EXPECTED_CHAIN_ID: chain-id guard
    function run() external returns (DeploymentAddresses memory addresses) {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address mpc = _getMpc();
        uint256 expectedChainId = vm.envUint("EXPECTED_CHAIN_ID");

        require(block.chainid == expectedChainId, "DeployExternalStack: chainid mismatch");
        require(mpc != address(0), "DeployExternalStack: MPC zero address");

        // Four CREATE transactions are broadcast in this exact order:
        // N: Vault implementation, N+1: Vault proxy, N+2: Executor, N+3: Router.
        uint256 startingNonce = vm.getNonce(deployer);
        address predictedRouter = vm.computeCreateAddress(deployer, startingNonce + 3);

        vm.startBroadcast(deployerPrivateKey);

        Vault vaultImplementation = new Vault();
        ERC1967Proxy vaultProxy =
            new ERC1967Proxy(address(vaultImplementation), abi.encodeCall(Vault.initialize, (deployer, mpc)));
        Vault vault = Vault(address(vaultProxy));

        Executor executor = new Executor(predictedRouter, address(vault));
        Router router = new Router(address(executor), address(vault));

        require(address(router) == predictedRouter, "DeployExternalStack: router prediction mismatch");

        vault.setExternalRouter(address(router));

        vm.stopBroadcast();

        addresses = DeploymentAddresses({
            vaultImplementation: address(vaultImplementation),
            vaultProxy: address(vault),
            executor: address(executor),
            router: address(router)
        });

        _verify(addresses, deployer, mpc);
        _printSummary(addresses, deployer, mpc);
    }

    function _verify(DeploymentAddresses memory addresses, address admin, address mpc) internal view {
        Vault vault = Vault(addresses.vaultProxy);
        Router router = Router(payable(addresses.router));
        Executor executor = Executor(payable(addresses.executor));

        require(addresses.vaultImplementation.code.length > 0, "DeployExternalStack: Vault impl missing");
        require(addresses.vaultProxy.code.length > 0, "DeployExternalStack: Vault proxy missing");
        require(addresses.executor.code.length > 0, "DeployExternalStack: Executor missing");
        require(addresses.router.code.length > 0, "DeployExternalStack: Router missing");

        require(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), admin), "DeployExternalStack: admin missing");
        require(vault.hasRole(keccak256("SETTLEMENT_VERIFIER_ROLE"), mpc), "DeployExternalStack: verifier missing");
        require(address(vault.intentRouter()) == addresses.router, "DeployExternalStack: Vault router mismatch");
        require(router.executor() == addresses.executor, "DeployExternalStack: Router executor mismatch");
        require(router.vault() == addresses.vaultProxy, "DeployExternalStack: Router vault mismatch");
        require(executor.gateway() == addresses.router, "DeployExternalStack: Executor gateway mismatch");
        require(executor.vault() == addresses.vaultProxy, "DeployExternalStack: Executor vault mismatch");
    }

    function _printSummary(DeploymentAddresses memory addresses, address admin, address mpc) internal pure {
        console.log("Chain deployment complete");
        console.log("Admin:", admin);
        console.log("MPC:", mpc);
        console.log("Vault implementation:", addresses.vaultImplementation);
        console.log("Vault proxy:", addresses.vaultProxy);
        console.log("Executor:", addresses.executor);
        console.log("Router:", addresses.router);
    }

    function _getMpc() internal view returns (address) {
        try vm.envAddress("MPC_ADDRESS") returns (address mpcAddress) {
            return mpcAddress;
        } catch {
            return vm.envAddress("MPC");
        }
    }
}
