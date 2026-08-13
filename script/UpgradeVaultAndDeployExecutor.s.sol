// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";

import {Executor} from "../src/Executor.sol";
import {Vault} from "../src/Vault.sol";
import {IMayanForwarder} from "../src/interfaces/IMayanForwarder.sol";

interface ICreateXUpgradeExecutor {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address);
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address);
}

interface IVaultUpgradeExecutor {
    function executor() external view returns (address);
    function grantRole(bytes32 role, address account) external;
    function hasRole(bytes32 role, address account) external view returns (bool);
    function setExecutor(address newExecutor) external;
    function upgradeToAndCall(address newImplementation, bytes memory data) external;
}

interface IERC1822ProxiableUpgradeExecutor {
    function proxiableUUID() external view returns (bytes32);
}

/// @title UpgradeVaultAndDeployExecutor
/// @notice Upgrades the configured Vault proxy and deploys its immutable Executor.
/// @dev The Executor is deliberately not installed automatically because `setExecutor` may need
/// to be submitted by a different DEFAULT_ADMIN_ROLE account (for example, a Safe). The script
/// prints both calldata and a ready-to-run `cast send` command for that final transaction.
/// AWS KMS broadcasts the deterministic deployments. `ADMIN_PRIVATE_KEY` broadcasts the Vault
/// upgrade and, when `CONFIGURE_EXECUTOR=true`, configures the Mayan target and selectors.
contract UpgradeVaultAndDeployExecutor is Script {
    address public constant DEFAULT_PROXY_ADDRESS = 0x86B60E813f9b739516dDbDc443526be5Ef8336aa;
    address public constant MAYAN_FORWARDER = 0x337685fdaB40D39bd02028545a4FfA7D287cC3E2;
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    ICreateXUpgradeExecutor public constant CREATEX =
        ICreateXUpgradeExecutor(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    function run() external returns (address newImplementation, address newExecutor) {
        address deployer = msg.sender;
        address admin = vm.envAddress("ADMIN");
        uint256 adminPrivateKey = vm.envUint("ADMIN_PRIVATE_KEY");
        address proxyAddress = vm.envOr("PROXY_ADDRESS", DEFAULT_PROXY_ADDRESS);
        bytes32 salt = vm.envBytes32("UPGRADE_SALT");
        bytes32 executorSalt = keccak256(abi.encodePacked(salt, "executor"));
        bool configureExecutor = vm.envBool("CONFIGURE_EXECUTOR");

        require(admin != address(0), "UpgradeExecutor: zero admin");
        require(vm.addr(adminPrivateKey) == admin, "UpgradeExecutor: admin key mismatch");
        require(proxyAddress.code.length > 0, "UpgradeExecutor: proxy has no code");

        address currentImplementation = _getImplementation(proxyAddress);
        require(currentImplementation.code.length > 0, "UpgradeExecutor: implementation has no code");

        IVaultUpgradeExecutor vault = IVaultUpgradeExecutor(proxyAddress);
        bool hasUpgraderRole = vault.hasRole(UPGRADER_ROLE, admin);
        bool hasAdminRole = vault.hasRole(DEFAULT_ADMIN_ROLE, admin);
        require(hasUpgraderRole || hasAdminRole, "UpgradeExecutor: admin cannot upgrade");

        bytes memory initCode = type(Vault).creationCode;
        newImplementation = CREATEX.computeCreate2Address(keccak256(abi.encode(salt)), keccak256(initCode));
        require(newImplementation.code.length == 0, "UpgradeExecutor: implementation already deployed");

        bytes memory executorInitCode = abi.encodePacked(type(Executor).creationCode, abi.encode(proxyAddress, admin));
        newExecutor = CREATEX.computeCreate2Address(keccak256(abi.encode(executorSalt)), keccak256(executorInitCode));
        require(newExecutor.code.length == 0, "UpgradeExecutor: executor already deployed");

        console.log("Deployer:", deployer);
        console.log("Executor admin:", admin);
        console.log("Vault proxy:", proxyAddress);
        console.log("Current implementation:", currentImplementation);
        console.log("Expected implementation:", newImplementation);
        console.log("Expected Executor:", newExecutor);
        console.log("Executor salt:", vm.toString(executorSalt));

        vm.startBroadcast();

        address deployedImplementation = CREATEX.deployCreate2(salt, initCode);
        require(deployedImplementation == newImplementation, "UpgradeExecutor: implementation mismatch");

        address deployedExecutor = CREATEX.deployCreate2(executorSalt, executorInitCode);
        require(deployedExecutor == newExecutor, "UpgradeExecutor: executor mismatch");

        vm.stopBroadcast();

        Executor executorContract = Executor(payable(newExecutor));
        require(
            IERC1822ProxiableUpgradeExecutor(newImplementation).proxiableUUID() == ERC1967_IMPLEMENTATION_SLOT,
            "UpgradeExecutor: invalid UUPS implementation"
        );

        vm.startBroadcast(adminPrivateKey);

        if (!hasUpgraderRole) {
            vault.grantRole(UPGRADER_ROLE, admin);
        }

        vault.upgradeToAndCall(newImplementation, "");

        if (configureExecutor) {
            _configureExecutor(executorContract);
        }

        vm.stopBroadcast();

        require(_getImplementation(proxyAddress) == newImplementation, "UpgradeExecutor: upgrade failed");
        require(executorContract.vault() == proxyAddress, "UpgradeExecutor: executor vault mismatch");
        require(executorContract.owner() == admin, "UpgradeExecutor: executor owner mismatch");
        if (configureExecutor) {
            _verifyExecutorConfiguration(executorContract);
        }

        bytes memory setExecutorCalldata = abi.encodeCall(IVaultUpgradeExecutor.setExecutor, (newExecutor));

        console.log("\n=== UPGRADE AND EXECUTOR DEPLOYMENT COMPLETE ===");
        console.log("New implementation:", newImplementation);
        console.log("New Executor:", newExecutor);
        console.log("Current Vault executor:", vault.executor());
        console.log("\n=== SET EXECUTOR (run as a Vault DEFAULT_ADMIN_ROLE account) ===");
        console.log("To:", proxyAddress);
        console.log("Value:", uint256(0));
        console.log("Data:");
        console.logBytes(setExecutorCalldata);
        console.log("Command:");
        console.log(
            string.concat(
                "cast send ",
                vm.toString(proxyAddress),
                ' "setExecutor(address)" ',
                vm.toString(newExecutor),
                ' --rpc-url "$RPC_URL" --private-key "$ADMIN_PRIVATE_KEY"'
            )
        );
    }

    function _getImplementation(address proxyAddress) internal view returns (address) {
        bytes32 implementation = vm.load(proxyAddress, ERC1967_IMPLEMENTATION_SLOT);
        return address(uint160(uint256(implementation)));
    }

    function _configureExecutor(Executor executorContract) internal {
        executorContract.setTarget(MAYAN_FORWARDER, true);
        executorContract.setSelector(MAYAN_FORWARDER, IMayanForwarder.forwardERC20.selector, true);
        executorContract.setSelector(MAYAN_FORWARDER, IMayanForwarder.swapAndForwardERC20.selector, true);
        executorContract.setSelector(MAYAN_FORWARDER, IMayanForwarder.swapAndForwardEth.selector, true);
    }

    function _verifyExecutorConfiguration(Executor executorContract) internal view {
        require(executorContract.allowedTarget(MAYAN_FORWARDER), "UpgradeExecutor: target not allowed");
        require(
            executorContract.allowedSelector(MAYAN_FORWARDER, IMayanForwarder.forwardERC20.selector),
            "UpgradeExecutor: forwardERC20 not allowed"
        );
        require(
            executorContract.allowedSelector(MAYAN_FORWARDER, IMayanForwarder.swapAndForwardERC20.selector),
            "UpgradeExecutor: swapAndForwardERC20 not allowed"
        );
        require(
            executorContract.allowedSelector(MAYAN_FORWARDER, IMayanForwarder.swapAndForwardEth.selector),
            "UpgradeExecutor: swapAndForwardEth not allowed"
        );
    }
}
