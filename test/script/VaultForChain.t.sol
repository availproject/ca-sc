// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {vaultCreationCode} from "../../script/VaultForChain.sol";
import {ArbitrumVault} from "../../src/ArbitrumVault.sol";
import {Vault} from "../../src/Vault.sol";
import {MockArbSys} from "../mocks/MockArbSys.sol";

contract VaultForChainHarness {
    function initCode() external view returns (bytes memory) {
        return vaultCreationCode();
    }
}

/// @dev One test, because `vm.setEnv` is process-wide and tests run in parallel
contract VaultForChainTest is Test {
    function test_VaultCreationCode_PicksArbitrumVaultExactlyOnNitro() public {
        VaultForChainHarness harness = new VaultForChainHarness();

        vm.setEnv("ARBITRUM_VAULT", "false");
        assertEq(harness.initCode(), type(Vault).creationCode);
        vm.setEnv("ARBITRUM_VAULT", "true");
        vm.expectRevert("VaultForChain: set ARBITRUM_VAULT exactly on Nitro chains");
        harness.initCode();

        vm.etch(address(100), address(new MockArbSys()).code);
        assertEq(harness.initCode(), type(ArbitrumVault).creationCode);
        vm.setEnv("ARBITRUM_VAULT", "false");
        vm.expectRevert("VaultForChain: set ARBITRUM_VAULT exactly on Nitro chains");
        harness.initCode();
    }
}
