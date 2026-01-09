// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract VaultTest is Test {
    Vault public vault;
    Vault public vaultImpl;
    MockERC20 public usdc;

    address public owner;
    address public user;
    address public solver;
    address public settlementVerifier;

    uint256 public ownerPk;
    uint256 public userPk;
    uint256 public solverPk;
    uint256 public settlementVerifierPk;

    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant SETTLEMENT_VERIFIER_ROLE = keccak256("SETTLEMENT_VERIFIER_ROLE");

    function setUp() public {
        ownerPk = 0x1;
        userPk = 0x2;
        solverPk = 0x3;
        settlementVerifierPk = 0x4;

        owner = vm.addr(ownerPk);
        user = vm.addr(userPk);
        solver = vm.addr(solverPk);
        settlementVerifier = vm.addr(settlementVerifierPk);

        usdc = new MockERC20("USD Coin", "USDC", 6);

        vaultImpl = new Vault();
        bytes memory initData = abi.encodeCall(Vault.initialize, (owner));
        ERC1967Proxy proxy = new ERC1967Proxy(address(vaultImpl), initData);
        vault = Vault(payable(address(proxy)));

        vm.prank(owner);
        vault.grantRole(SETTLEMENT_VERIFIER_ROLE, settlementVerifier);

        vm.deal(user, 100 ether);
        vm.deal(solver, 100 ether);
        vm.deal(address(vault), 1 ether);
    }

    function _addressToBytes32(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }

    function _createRequest(
        address sourceToken,
        uint256 sourceAmount,
        address destToken,
        uint256 destAmount,
        uint256 destChainId,
        uint256 nonce,
        uint256 expiry,
        address userAddr
    ) internal view returns (Vault.Request memory) {
        Vault.SourcePair[] memory sources = new Vault.SourcePair[](1);
        sources[0] = Vault.SourcePair({
            universe: Vault.Universe.ETHEREUM,
            chainID: block.chainid,
            contractAddress: _addressToBytes32(sourceToken),
            value: sourceAmount
        });

        Vault.DestinationPair[] memory destinations = new Vault.DestinationPair[](1);
        destinations[0] = Vault.DestinationPair({
            contractAddress: _addressToBytes32(destToken),
            value: destAmount
        });

        Vault.Party[] memory parties = new Vault.Party[](1);
        parties[0] = Vault.Party({
            universe: Vault.Universe.ETHEREUM,
            address_: _addressToBytes32(userAddr)
        });

        return Vault.Request({
            sources: sources,
            destinationUniverse: Vault.Universe.ETHEREUM,
            destinationChainID: destChainId,
            recipientAddress: _addressToBytes32(userAddr),
            destinations: destinations,
            nonce: nonce,
            expiry: expiry,
            parties: parties
        });
    }

    function _hashRequest(Vault.Request memory request) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                request.sources,
                request.destinationUniverse,
                request.destinationChainID,
                request.recipientAddress,
                request.destinations,
                request.nonce,
                request.expiry,
                request.parties
            )
        );
    }

    function _signRequest(Vault.Request memory request, uint256 pk) internal pure returns (bytes memory) {
        bytes32 requestHash = _hashRequest(request);
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", requestHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    function test_Initialize_AssignsAdminRole() public view {
        assertTrue(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), owner));
    }

    function test_Initialize_AssignsUpgraderRole() public view {
        assertTrue(vault.hasRole(UPGRADER_ROLE, owner));
    }

    function test_NonAdmin_DoesNotHaveAdminRole() public view {
        assertFalse(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), user));
    }

    function test_Deposit_ERC20Tokens() public {
        uint256 amount = 1000e6;
        uint256 nonce = 1;
        uint256 expiry = block.timestamp + 1 hours;

        usdc.mint(user, amount);

        vm.prank(user);
        usdc.approve(address(vault), amount);

        Vault.Request memory request = _createRequest(
            address(usdc),
            amount,
            address(usdc),
            amount,
            2,
            nonce,
            expiry,
            user
        );

        bytes memory signature = _signRequest(request, userPk);

        vm.expectEmit(true, false, false, true);
        emit Vault.Deposit(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hashRequest(request))),
            user
        );

        vault.deposit(request, signature, 0);

        assertEq(usdc.balanceOf(user), 0);
        assertEq(usdc.balanceOf(address(vault)), amount);
    }

    function test_Deposit_NativeTokens() public {
        uint256 amount = 1 ether;
        uint256 nonce = 1;
        uint256 expiry = block.timestamp + 1 hours;

        Vault.Request memory request = _createRequest(
            address(0),
            amount,
            address(0),
            amount,
            2,
            nonce,
            expiry,
            user
        );

        bytes memory signature = _signRequest(request, userPk);

        uint256 vaultBalanceBefore = address(vault).balance;

        vault.deposit{value: amount}(request, signature, 0);

        assertEq(address(vault).balance, vaultBalanceBefore + amount);
    }

    function test_Deposit_RevertsOnDuplicateNonce() public {
        uint256 amount = 1000e6;
        uint256 nonce = 1;
        uint256 expiry = block.timestamp + 1 hours;

        usdc.mint(user, amount * 2);

        vm.prank(user);
        usdc.approve(address(vault), amount * 2);

        Vault.Request memory request = _createRequest(
            address(usdc),
            amount,
            address(usdc),
            amount,
            2,
            nonce,
            expiry,
            user
        );

        bytes memory signature = _signRequest(request, userPk);

        vault.deposit(request, signature, 0);

        vm.expectRevert("Vault: Nonce already used");
        vault.deposit(request, signature, 0);
    }

    function test_Deposit_RevertsOnExpiredRequest() public {
        uint256 amount = 1000e6;
        uint256 nonce = 1;
        uint256 expiry = block.timestamp - 1;

        usdc.mint(user, amount);

        vm.prank(user);
        usdc.approve(address(vault), amount);

        Vault.Request memory request = _createRequest(
            address(usdc),
            amount,
            address(usdc),
            amount,
            2,
            nonce,
            expiry,
            user
        );

        bytes memory signature = _signRequest(request, userPk);

        vm.expectRevert("Vault: Request expired");
        vault.deposit(request, signature, 0);
    }

    function test_Fulfil_TransfersTokensToRecipient() public {
        uint256 amount = 1000e6;
        uint256 nonce = 1;
        uint256 expiry = block.timestamp + 1 hours;

        usdc.mint(solver, amount);

        vm.prank(solver);
        usdc.approve(address(vault), amount);

        Vault.Request memory request = _createRequest(
            address(usdc),
            amount,
            address(usdc),
            amount,
            block.chainid,
            nonce,
            expiry,
            user
        );

        bytes memory signature = _signRequest(request, userPk);

        vm.prank(solver);
        vault.fulfil(request, signature);

        assertEq(usdc.balanceOf(user), amount);
    }

    function test_Fulfil_NativeTokens() public {
        uint256 amount = 1 ether;
        uint256 nonce = 1;
        uint256 expiry = block.timestamp + 1 hours;

        Vault.Request memory request = _createRequest(
            address(0),
            amount,
            address(0),
            amount,
            block.chainid,
            nonce,
            expiry,
            user
        );

        bytes memory signature = _signRequest(request, userPk);

        uint256 userBalanceBefore = user.balance;

        vm.prank(solver);
        vault.fulfil{value: amount}(request, signature);

        assertEq(user.balance, userBalanceBefore + amount);
    }

    function test_Fulfil_RevertsOnDuplicateNonce() public {
        uint256 amount = 1000e6;
        uint256 nonce = 1;
        uint256 expiry = block.timestamp + 1 hours;

        usdc.mint(solver, amount * 2);

        vm.prank(solver);
        usdc.approve(address(vault), amount * 2);

        Vault.Request memory request = _createRequest(
            address(usdc),
            amount,
            address(usdc),
            amount,
            block.chainid,
            nonce,
            expiry,
            user
        );

        bytes memory signature = _signRequest(request, userPk);

        vm.prank(solver);
        vault.fulfil(request, signature);

        vm.prank(solver);
        vm.expectRevert("Vault: Nonce already used");
        vault.fulfil(request, signature);
    }

    function test_Settle_TransfersToSolvers() public {
        uint256 erc20Amount = 1000e6;
        uint256 nativeAmount = 1 ether;

        usdc.mint(address(vault), erc20Amount);

        address[] memory solvers_ = new address[](2);
        solvers_[0] = solver;
        solvers_[1] = solver;

        address[] memory tokens = new address[](2);
        tokens[0] = address(usdc);
        tokens[1] = address(0);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = erc20Amount;
        amounts[1] = nativeAmount;

        uint256 nonce = 1;

        Vault.SettleData memory settleData = Vault.SettleData({
            universe: Vault.Universe.ETHEREUM,
            chainID: block.chainid,
            solvers: solvers_,
            contractAddresses: tokens,
            amounts: amounts,
            nonce: nonce
        });

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
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(settlementVerifierPk, ethSignedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 solverUsdcBefore = usdc.balanceOf(solver);
        uint256 solverEthBefore = solver.balance;

        vault.settle(settleData, signature);

        assertEq(usdc.balanceOf(solver), solverUsdcBefore + erc20Amount);
        assertEq(solver.balance, solverEthBefore + nativeAmount);
    }

    function test_Settle_RevertsOnDuplicateNonce() public {
        uint256 amount = 1000e6;

        usdc.mint(address(vault), amount * 2);

        address[] memory solvers_ = new address[](1);
        solvers_[0] = solver;

        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;

        uint256 nonce = 1;

        Vault.SettleData memory settleData = Vault.SettleData({
            universe: Vault.Universe.ETHEREUM,
            chainID: block.chainid,
            solvers: solvers_,
            contractAddresses: tokens,
            amounts: amounts,
            nonce: nonce
        });

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
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(settlementVerifierPk, ethSignedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vault.settle(settleData, signature);

        vm.expectRevert("Vault: Nonce already used");
        vault.settle(settleData, signature);
    }

    function test_Settle_RevertsWithInvalidSigner() public {
        uint256 amount = 1000e6;

        usdc.mint(address(vault), amount);

        address[] memory solvers_ = new address[](1);
        solvers_[0] = solver;

        address[] memory tokens = new address[](1);
        tokens[0] = address(usdc);

        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;

        uint256 nonce = 1;

        Vault.SettleData memory settleData = Vault.SettleData({
            universe: Vault.Universe.ETHEREUM,
            chainID: block.chainid,
            solvers: solvers_,
            contractAddresses: tokens,
            amounts: amounts,
            nonce: nonce
        });

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
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userPk, ethSignedHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert("Vault: Invalid signature");
        vault.settle(settleData, signature);
    }

    function test_VerifyRequestSignature() public view {
        uint256 amount = 1000e6;
        uint256 nonce = 1;
        uint256 expiry = block.timestamp + 1 hours;

        Vault.Request memory request = _createRequest(
            address(usdc),
            amount,
            address(usdc),
            amount,
            2,
            nonce,
            expiry,
            user
        );

        bytes memory signature = _signRequest(request, userPk);

        (bool valid, bytes32 hash) = vault.verifyRequestSignature(request, signature);

        assertTrue(valid);
        assertEq(
            hash,
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _hashRequest(request)))
        );
    }

    receive() external payable {}
}
