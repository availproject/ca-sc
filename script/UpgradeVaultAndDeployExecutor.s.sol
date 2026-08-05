// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";

import {Executor} from "../src/Executor.sol";
import {Vault} from "../src/Vault.sol";

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
contract UpgradeVaultAndDeployExecutor is Script {
    address public constant DEFAULT_PROXY_ADDRESS = 0x86B60E813f9b739516dDbDc443526be5Ef8336aa;
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    ICreateXUpgradeExecutor public constant CREATEX =
        ICreateXUpgradeExecutor(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    function run() external returns (address newImplementation, address newExecutor) {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);
        address proxyAddress = vm.envOr("PROXY_ADDRESS", DEFAULT_PROXY_ADDRESS);
        address executorOwner = vm.envOr("EXECUTOR_OWNER", deployer);
        bytes32 salt = vm.envBytes32("UPGRADE_SALT");

        require(proxyAddress.code.length > 0, "UpgradeExecutor: proxy has no code");
        require(executorOwner != address(0), "UpgradeExecutor: zero executor owner");

        address currentImplementation = _getImplementation(proxyAddress);
        require(currentImplementation.code.length > 0, "UpgradeExecutor: implementation has no code");

        IVaultUpgradeExecutor vault = IVaultUpgradeExecutor(proxyAddress);
        bool hasUpgraderRole = vault.hasRole(UPGRADER_ROLE, deployer);
        bool hasAdminRole = vault.hasRole(DEFAULT_ADMIN_ROLE, deployer);
        require(hasUpgraderRole || hasAdminRole, "UpgradeExecutor: signer cannot upgrade");

        bytes memory initCode = type(Vault).creationCode;
        newImplementation = CREATEX.computeCreate2Address(keccak256(abi.encode(salt)), keccak256(initCode));
        require(newImplementation.code.length == 0, "UpgradeExecutor: implementation already deployed");

        console.log("Deployer:", deployer);
        console.log("Vault proxy:", proxyAddress);
        console.log("Current implementation:", currentImplementation);
        console.log("Expected implementation:", newImplementation);
        console.log("Executor owner:", executorOwner);

        vm.startBroadcast(privateKey);

        if (!hasUpgraderRole) {
            vault.grantRole(UPGRADER_ROLE, deployer);
        }

        address deployedImplementation = CREATEX.deployCreate2(salt, initCode);
        require(deployedImplementation == newImplementation, "UpgradeExecutor: implementation mismatch");
        require(
            IERC1822ProxiableUpgradeExecutor(newImplementation).proxiableUUID() == ERC1967_IMPLEMENTATION_SLOT,
            "UpgradeExecutor: invalid UUPS implementation"
        );

        vault.upgradeToAndCall(newImplementation, "");

        Executor executorContract = new Executor(proxyAddress, executorOwner);
        newExecutor = address(executorContract);

        vm.stopBroadcast();

        require(_getImplementation(proxyAddress) == newImplementation, "UpgradeExecutor: upgrade failed");
        require(executorContract.vault() == proxyAddress, "UpgradeExecutor: executor vault mismatch");
        require(executorContract.owner() == executorOwner, "UpgradeExecutor: executor owner mismatch");

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
}
