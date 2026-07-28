// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {ICreateX} from "createx-forge/src/ICreateX.sol";
import {Router} from "../src/Router.sol";
import {Executor} from "../src/Executor.sol";

/// @title DeployExternalPair
/// @author Rachit Anand Srivastava (@privacy_prophet)
/// @notice Deterministically deploys the immutable Router/Executor pair via the canonical
/// CreateX factory. The Router must know the Executor's address and the Executor must know
/// the Router's address, so each contract's init code embeds the other's address.
/// @dev WHY CREATE3 and not CREATE2: a CREATE2 address commits to the init-code hash, and
/// here each contract's init code contains the other contract's address, so the two
/// addresses can only be known after both init codes are fully formed — a circular
/// dependency that cannot be resolved. CREATE3 derives the deployed address from only
/// (factory, salt), never from the init code, which breaks the cycle: the Router's address
/// is predicted up front, the Executor is constructed with that prediction, and the Router
/// is then deployed and required to land on it.
/// @dev CreateX guards salts: the first 20 bytes must equal the caller (msg.sender) or be
/// zero, and the 21st byte selects cross-chain redeploy protection. This script embeds the
/// deployer in the first 20 bytes (permissioned deploy protection, so only the deployer key
/// can create the pair at the predicted addresses), sets the 21st byte to 0x00 (no
/// cross-chain redeploy protection, so the same (deployer, SALT) yields the same addresses
/// on every chain), and takes the remaining 11 bytes from the derived hash. For such a
/// permissioned salt CreateX internally rewrites it to
/// keccak256(abi.encode(msg.sender, salt)) before deriving the CREATE3 address from
/// (factory, guardedSalt) only, so predictions below must apply the same rewrite before
/// calling the single-argument computeCreate3Address (which uses CreateX itself as the
/// CREATE2 deployer of its proxy).
contract DeployExternalPair is Script {
    /// @notice The canonical CreateX factory deployed on all supported chains.
    ICreateX public constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(deployerPrivateKey);
        address vault = vm.envAddress("VAULT_ADDRESS");
        uint256 expectedChainId = vm.envUint("EXPECTED_CHAIN_ID");
        bytes32 salt = vm.envBytes32("SALT");

        require(block.chainid == expectedChainId, "DeployExternalPair: chainid mismatch");
        require(vault.code.length > 0, "DeployExternalPair: vault has no code");

        bytes32 routerSalt = _guardedSalt(keccak256(abi.encode(salt, "router")), deployer);
        bytes32 executorSalt = _guardedSalt(keccak256(abi.encode(salt, "executor")), deployer);

        // Mirror the CreateX guard rewrite for permissioned salts (see contract NatSpec).
        bytes32 guardedRouterSalt = keccak256(abi.encode(deployer, routerSalt));
        bytes32 guardedExecutorSalt = keccak256(abi.encode(deployer, executorSalt));

        // CREATE3 addresses are independent of init code, so the Router address is known
        // before either contract exists.
        address predictedRouter = CREATEX.computeCreate3Address(guardedRouterSalt);

        vm.startBroadcast(deployerPrivateKey);

        address executorAddr = CREATEX.deployCreate3(
            executorSalt, abi.encodePacked(type(Executor).creationCode, abi.encode(predictedRouter, vault))
        );
        require(
            executorAddr == CREATEX.computeCreate3Address(guardedExecutorSalt),
            "DeployExternalPair: executor address mismatch"
        );

        address routerAddr =
            CREATEX.deployCreate3(routerSalt, abi.encodePacked(type(Router).creationCode, abi.encode(executorAddr)));
        require(routerAddr == predictedRouter, "DeployExternalPair: router address mismatch");

        vm.stopBroadcast();

        console.log("Chain ID:", block.chainid);
        console.log("Vault:", vault);
        console.log("Salt (router):", vm.toString(routerSalt));
        console.log("Salt (executor):", vm.toString(executorSalt));
        console.log("Predicted router:", predictedRouter);
        console.log("Router:", routerAddr);
        console.log("Executor:", executorAddr);

        require(Router(routerAddr).executor() == executorAddr, "DeployExternalPair: router executor mismatch");
        require(
            Executor(payable(executorAddr)).gateway() == routerAddr, "DeployExternalPair: executor gateway mismatch"
        );
        require(Executor(payable(executorAddr)).vault() == vault, "DeployExternalPair: executor vault mismatch");
    }

    /// @dev Maps an arbitrary derived hash to a salt that passes the CreateX guard:
    /// first 20 bytes = deployer, 21st byte = 0x00, last 11 bytes from `raw`.
    function _guardedSalt(bytes32 raw, address deployer) internal pure returns (bytes32) {
        return bytes32(abi.encodePacked(bytes20(deployer), bytes1(0x00), bytes11(uint88(uint256(raw)))));
    }
}
