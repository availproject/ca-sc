// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

// Imports
import {BaseVaultTest} from "../../BaseVaultTest.t.sol";
import {Vault} from "../../../contracts/Vault.sol";

// AccessControlTest - Access control tests for Vault.sol
// @title AccessControlTest
// @notice Tests for access control including upgrade, settlement verification, and admin roles
// @dev Tests role-based permissions, signature verification, and revert conditions
contract AccessControlTest is BaseVaultTest {
    // State Variables

    /// @notice Test private key for settlement verifier signature generation
    uint256 public constant VERIFIER_PRIVATE_KEY = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;

    // Setup

    /// @notice Sets up the test environment with verifier role and vault funding
    function setUp() public virtual override {
        super.setUp();

        // Fund vault with ETH for settlement tests
        vm.deal(address(vault), 10 ether);

        // Get the verifier address from private key and grant role
        address verifierFromKey = vm.addr(VERIFIER_PRIVATE_KEY);
        vm.prank(admin);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, verifierFromKey);
    }

    // Helper Functions

    /// @notice Converts an address to a single-element address array
    function _toAddressArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }

    /// @notice Converts a uint256 to a single-element uint256 array
    function _toUintArray(uint256 val) internal pure returns (uint256[] memory) {
        uint256[] memory arr = new uint256[](1);
        arr[0] = val;
        return arr;
    }

    // Upgrade Tests

    /// @notice Test UPGRADER_ROLE can upgrade contract
    function test_Upgrade_UpgraderRole_Success() public {
        // Deploy new implementation
        Vault newImplementation = new Vault();

        // Upgrade as admin (has UPGRADER_ROLE)
        vm.prank(admin);
        vault.upgradeToAndCall(address(newImplementation), "");

        // If we get here, upgrade succeeded
        assertTrue(true, "Upgrade should succeed with UPGRADER_ROLE");
    }

    /// @notice Test non-UPGRADER cannot upgrade
    function test_Upgrade_NonUpgrader_Reverts() public {
        Vault newImplementation = new Vault();

        // Try to upgrade as user (no UPGRADER_ROLE)
        vm.expectRevert();
        vm.prank(user);
        vault.upgradeToAndCall(address(newImplementation), "");
    }

    // Settlement Verifier Tests

    /// @notice Test SETTLEMENT_VERIFIER_ROLE can settle
    function test_Settle_VerifierRole_Success() public view {
        // This is tested in test_Settle_SingleSolverETH_Success
        // The verifier key is granted SETTLEMENT_VERIFIER_ROLE in setUp
        address verifierFromKey = vm.addr(VERIFIER_PRIVATE_KEY);
        assertTrue(vault.hasRole(SETTLEMENT_VERIFIER_ROLE, verifierFromKey), "Verifier should have role");
    }

    /// @notice Test non-verifier cannot settle
    function test_Settle_NonVerifier_Reverts() public {
        uint256 settleAmount = 0.5 ether;
        uint256 nonce = 36;

        Vault.SettleData memory settleData = _createSimpleSettleData(solver, address(0), settleAmount, nonce);

        // Sign with non-verifier key
        uint256 nonVerifierKey = 0x9999999999999999999999999999999999999999999999999999999999999999;
        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.solvers,
                settleData.contractAddresses,
                settleData.amounts,
                settleData.nonce
            )
        );
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(nonVerifierKey, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Verify the signer doesn't have the role
        address nonVerifier = vm.addr(nonVerifierKey);
        assertFalse(vault.hasRole(SETTLEMENT_VERIFIER_ROLE, nonVerifier), "Non-verifier should not have role");

        vm.expectRevert("Vault: Invalid signature");
        vm.prank(user);
        vault.settle(settleData, signature);
    }

    // Admin Role Tests

    /// @notice Test DEFAULT_ADMIN_ROLE can grant roles
    function test_AccessControl_AdminCanGrantRole() public {
        address newVerifier = makeAddr("newVerifier");

        vm.prank(admin);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, newVerifier);

        assertTrue(vault.hasRole(SETTLEMENT_VERIFIER_ROLE, newVerifier), "Admin should be able to grant role");
    }

    /// @notice Test non-admin cannot grant roles
    function test_AccessControl_NonAdminCannotGrantRole() public {
        address newVerifier = makeAddr("newVerifier");

        vm.expectRevert();
        vm.prank(user);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, newVerifier);
    }

    // Settle Revert Tests - Invalid Signature

    /// @notice Test settle reverts with invalid signature (not SETTLEMENT_VERIFIER_ROLE)
    function test_Settle_InvalidSignature_Reverts() public {
        uint256 settleAmount = 0.5 ether;
        uint256 nonce = 23;

        Vault.SettleData memory settleData = _createSimpleSettleData(solver, address(0), settleAmount, nonce);

        // Sign with wrong key (not verifier)
        uint256 wrongKey = 0x9999999999999999999999999999999999999999999999999999999999999999;
        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.solvers,
                settleData.contractAddresses,
                settleData.amounts,
                settleData.nonce
            )
        );
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongKey, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("Vault: Invalid signature");
        vm.prank(user);
        vault.settle(settleData, signature);
    }

    // Settle Revert Tests - Length Mismatches

    /// @notice Test settle reverts when solvers length != contractAddresses length
    function test_Settle_TokenLengthMismatch_Reverts() public {
        uint256 nonce = 24;

        // Create mismatched arrays
        address[] memory solvers = new address[](2);
        solvers[0] = solver;
        solvers[1] = makeAddr("solver2");

        address[] memory contractAddresses = new address[](1); // Mismatched length
        contractAddresses[0] = address(0);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 0.5 ether;
        amounts[1] = 0.5 ether;

        Vault.SettleData memory settleData =
            _createSettleData(Vault.Universe.ETHEREUM, block.chainid, solvers, contractAddresses, amounts, nonce);

        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.solvers,
                settleData.contractAddresses,
                settleData.amounts,
                settleData.nonce
            )
        );
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("tokens length mismatch");
        vm.prank(user);
        vault.settle(settleData, signature);
    }

    /// @notice Test settle reverts when solvers length != amounts length
    function test_Settle_AmountsLengthMismatch_Reverts() public {
        uint256 nonce = 25;

        // Create mismatched arrays
        address[] memory solvers = new address[](2);
        solvers[0] = solver;
        solvers[1] = makeAddr("solver2");

        address[] memory contractAddresses = new address[](2);
        contractAddresses[0] = address(0);
        contractAddresses[1] = address(token);

        uint256[] memory amounts = new uint256[](1); // Mismatched length
        amounts[0] = 0.5 ether;

        Vault.SettleData memory settleData =
            _createSettleData(Vault.Universe.ETHEREUM, block.chainid, solvers, contractAddresses, amounts, nonce);

        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.solvers,
                settleData.contractAddresses,
                settleData.amounts,
                settleData.nonce
            )
        );
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("amounts length mismatch");
        vm.prank(user);
        vault.settle(settleData, signature);
    }

    // Settle Revert Tests - Nonce, ChainID, Universe

    /// @notice Test settle reverts when nonce already used
    function test_Settle_NonceAlreadyUsed_Reverts() public {
        uint256 settleAmount = 0.5 ether;
        uint256 nonce = 26;

        Vault.SettleData memory settleData = _createSimpleSettleData(solver, address(0), settleAmount, nonce);

        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.solvers,
                settleData.contractAddresses,
                settleData.amounts,
                settleData.nonce
            )
        );
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // First settle
        vm.prank(user);
        vault.settle(settleData, signature);

        // Second settle with same nonce should revert
        vm.expectRevert("Vault: Nonce already used");
        vm.prank(user);
        vault.settle(settleData, signature);
    }

    /// @notice Test settle reverts with wrong chainID
    function test_Settle_WrongChainID_Reverts() public {
        uint256 settleAmount = 0.5 ether;
        uint256 nonce = 27;

        // Create settle data with wrong chainID
        address[] memory solvers = new address[](1);
        solvers[0] = solver;

        address[] memory contractAddresses = new address[](1);
        contractAddresses[0] = address(0);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = settleAmount;

        Vault.SettleData memory settleData = _createSettleData(
            Vault.Universe.ETHEREUM,
            999999, // Wrong chainID
            solvers,
            contractAddresses,
            amounts,
            nonce
        );

        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.solvers,
                settleData.contractAddresses,
                settleData.amounts,
                settleData.nonce
            )
        );
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("Vault: Chain ID mismatch");
        vm.prank(user);
        vault.settle(settleData, signature);
    }

    /// @notice Test settle reverts with wrong universe
    function test_Settle_WrongUniverse_Reverts() public {
        uint256 settleAmount = 0.5 ether;
        uint256 nonce = 28;

        Vault.SettleData memory settleData = _createSettleData(
            Vault.Universe.SOLANA, // Wrong universe
            block.chainid,
            _toAddressArray(solver),
            _toAddressArray(address(0)),
            _toUintArray(settleAmount),
            nonce
        );

        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.solvers,
                settleData.contractAddresses,
                settleData.amounts,
                settleData.nonce
            )
        );
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("Vault: Universe mismatch");
        vm.prank(user);
        vault.settle(settleData, signature);
    }

    // ETH Transfer Failure Test

    /// @notice Test settle reverts when ETH transfer fails
    function test_Settle_ETHTransferFailed_Reverts() public {
        uint256 settleAmount = 0.5 ether;
        uint256 nonce = 29;

        // Create a contract that rejects ETH
        ETHRejecter rejecter = new ETHRejecter();

        Vault.SettleData memory settleData = _createSimpleSettleData(address(rejecter), address(0), settleAmount, nonce);

        bytes32 structHash = keccak256(
            abi.encode(
                settleData.universe,
                settleData.chainID,
                settleData.solvers,
                settleData.contractAddresses,
                settleData.amounts,
                settleData.nonce
            )
        );
        bytes32 signatureHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VERIFIER_PRIVATE_KEY, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("Vault: Transfer failed");
        vm.prank(user);
        vault.settle(settleData, signature);
    }
}

// Helper Contract for Testing ETH Transfer Failures

/// @notice Contract that rejects ETH transfers
contract ETHRejecter {
    receive() external payable {
        revert("ETH rejected");
    }

    fallback() external payable {
        revert("ETH rejected");
    }
}
