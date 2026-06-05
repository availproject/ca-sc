// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {Vault} from "../src/Vault.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {Universe} from "../src/types.sol";
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
    bytes32 private constant VAULT_UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    struct DeploymentAddresses {
        address vaultProxy;
        address mayanRouter;
        address admin;
    }

    function run() external returns (DeploymentAddresses memory addresses) {
        address admin = vm.envAddress("ADMIN_ADDRESS");
        address finalAdmin = vm.envAddress("FINAL_ADMIN_ADDRESS");
        address mpc = _getMpc();
        uint256 adminPrivateKey = vm.envUint("PRIVATE_KEY");

        require(finalAdmin != address(0), "DeployAll: Final admin zero address");
        require(vm.addr(adminPrivateKey) == admin, "DeployAll: PRIVATE_KEY must match ADMIN_ADDRESS");

        addresses.admin = finalAdmin;

        vm.startBroadcast();

        // Base version used to derive all CREATE2 salts deterministically
        string memory baseVersion = "1.1.0";

        console.log("\n========== Deploying Vault (createX) ==========");
        bytes32 vaultSalt = keccak256(abi.encodePacked("nexus-mayan-vault-", baseVersion));
        bytes32 proxySalt = keccak256(abi.encodePacked(vaultSalt, "proxy"));

        bytes memory vaultInitCode = type(Vault).creationCode;
        bytes32 vaultInitCodeHash = keccak256(vaultInitCode);
        address expectedImpl = CREATEX.computeCreate2Address(keccak256(abi.encode(vaultSalt)), vaultInitCodeHash);
        console.log("Expected implementation:", expectedImpl);

        bytes memory initData = abi.encodeWithSelector(Vault.initialize.selector, admin, mpc);
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

        console.log("\n========== Deploying MayanRouter (createX) ==========");
        bytes32 mayanSalt = keccak256(abi.encodePacked("nexus-mayan-mayanrouter-", baseVersion));
        bytes32 mayanProxySalt = keccak256(abi.encodePacked(mayanSalt, "proxy"));

        bytes memory mayanInitCode = type(MayanRouter).creationCode;
        bytes32 mayanInitCodeHash = keccak256(mayanInitCode);
        address expectedMayanImpl = CREATEX.computeCreate2Address(keccak256(abi.encode(mayanSalt)), mayanInitCodeHash);
        console.log("Expected MayanRouter implementation:", expectedMayanImpl);

        (
            Universe[] memory universes,
            uint256[] memory chainIds,
            uint16[] memory wormholeChainIds,
            uint16[] memory tokenWormholeChainIds,
            address[] memory tokens,
            uint8[] memory decimals
        ) = _mayanConfiguration();

        bytes memory mayanRouterInitData = abi.encodeWithSelector(
            MayanRouter.initialize.selector,
            admin,
            universes,
            chainIds,
            wormholeChainIds,
            tokenWormholeChainIds,
            tokens,
            decimals
        );
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

        vm.stopBroadcast();

        console.log("\n========== Configuring contracts as admin ==========");
        vm.startBroadcast(adminPrivateKey);

        vault.setRouter(addresses.mayanRouter);
        console.log("MayanRouter set as Vault router");

        MayanRouter mayanRouter = MayanRouter(addresses.mayanRouter);
        mayanRouter.grantRole(mayanRouter.VAULT_ROLE(), addresses.vaultProxy);
        console.log("Vault granted MayanRouter VAULT_ROLE");

        _transferOwnership(vault, mayanRouter, admin, finalAdmin);

        vm.stopBroadcast();

        console.log("\n========== Verifying Deployment ==========");
        _verifyDeployment(addresses, admin);

        _printSummary(addresses);

        return addresses;
    }

    function _transferOwnership(Vault vault, MayanRouter mayanRouter, address admin, address finalAdmin) internal {
        if (finalAdmin == admin) {
            console.log("Final admin is already the active admin");
            return;
        }

        console.log("\n========== Transferring ownership to final admin ==========");

        vault.grantRole(vault.DEFAULT_ADMIN_ROLE(), finalAdmin);
        vault.grantRole(VAULT_UPGRADER_ROLE, finalAdmin);
        vault.revokeRole(VAULT_UPGRADER_ROLE, admin);
        vault.revokeRole(vault.DEFAULT_ADMIN_ROLE(), admin);
        console.log("Vault admin and upgrader roles transferred to:", finalAdmin);

        mayanRouter.grantRole(mayanRouter.DEFAULT_ADMIN_ROLE(), finalAdmin);
        mayanRouter.grantRole(mayanRouter.UPGRADER_ROLE(), finalAdmin);
        mayanRouter.transferOwnership(finalAdmin);
        mayanRouter.revokeRole(mayanRouter.UPGRADER_ROLE(), admin);
        mayanRouter.revokeRole(mayanRouter.DEFAULT_ADMIN_ROLE(), admin);
        console.log("MayanRouter ownership, admin, and upgrader roles transferred to:", finalAdmin);
    }

    function _verifyDeployment(DeploymentAddresses memory addresses, address initialAdmin) internal view {
        Vault vault = Vault(payable(addresses.vaultProxy));

        require(vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), addresses.admin), "Vault: Admin role not granted");
        require(vault.hasRole(VAULT_UPGRADER_ROLE, addresses.admin), "Vault: Upgrader role not granted");
        require(vault.hasRole(keccak256("SETTLEMENT_VERIFIER_ROLE"), _getMpc()), "Vault: MPC role not granted");
        require(address(vault.router()) == addresses.mayanRouter, "Vault: MayanRouter not set");
        require(
            MayanRouter(addresses.mayanRouter)
                .hasRole(MayanRouter(addresses.mayanRouter).VAULT_ROLE(), addresses.vaultProxy),
            "MayanRouter: Vault role not granted"
        );

        MayanRouter mayanRouter = MayanRouter(addresses.mayanRouter);
        require(mayanRouter.owner() == addresses.admin, "MayanRouter: Owner not transferred");
        require(mayanRouter.hasRole(mayanRouter.DEFAULT_ADMIN_ROLE(), addresses.admin), "MayanRouter: Admin not set");
        require(mayanRouter.hasRole(mayanRouter.UPGRADER_ROLE(), addresses.admin), "MayanRouter: Upgrader not set");

        if (initialAdmin != addresses.admin) {
            require(!vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), initialAdmin), "Vault: Initial admin still admin");
            require(!vault.hasRole(VAULT_UPGRADER_ROLE, initialAdmin), "Vault: Initial admin still upgrader");
            require(
                !mayanRouter.hasRole(mayanRouter.DEFAULT_ADMIN_ROLE(), initialAdmin),
                "MayanRouter: Initial admin still admin"
            );
            require(
                !mayanRouter.hasRole(mayanRouter.UPGRADER_ROLE(), initialAdmin),
                "MayanRouter: Initial admin still upgrader"
            );
        }

        require(mayanRouter.wormholeChainID(Universe.ETHEREUM, 143) == 48, "MayanRouter: Monad mapping missing");
        require(mayanRouter.wormholeChainID(Universe.ETHEREUM, 999) == 47, "MayanRouter: HyperEVM mapping missing");
        require(
            mayanRouter.tokenOutDecimals(30, 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913) == 6,
            "MayanRouter: Base USDC decimals missing"
        );
        require(
            mayanRouter.tokenOutDecimals(48, 0x754704Bc059F8C67012fEd69BC8A327a5aafb603) == 6,
            "MayanRouter: Monad USDC decimals missing"
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

    function _getMpc() internal view returns (address) {
        try vm.envAddress("MPC_ADDRESS") returns (address mpcAddress) {
            return mpcAddress;
        } catch {}

        return vm.envAddress("MPC");
    }

    function _mayanConfiguration()
        internal
        pure
        returns (
            Universe[] memory universes,
            uint256[] memory chainIds,
            uint16[] memory wormholeChainIds,
            uint16[] memory tokenWormholeChainIds,
            address[] memory tokens,
            uint8[] memory decimals
        )
    {
        universes = new Universe[](9);
        chainIds = new uint256[](9);
        wormholeChainIds = new uint16[](9);

        _setWormholeConfig(universes, chainIds, wormholeChainIds);

        tokenWormholeChainIds = new uint16[](27);
        tokens = new address[](27);
        decimals = new uint8[](27);

        _setNativeTokenDecimals(tokenWormholeChainIds, tokens, decimals);
        _setUsdcTokenDecimals(tokenWormholeChainIds, tokens, decimals);
    }

    function _setWormholeConfig(
        Universe[] memory universes,
        uint256[] memory chainIds,
        uint16[] memory wormholeChainIds
    ) internal pure {
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 0, 1, 2);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 1, 56, 4);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 2, 137, 5);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 3, 43_114, 6);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 4, 42_161, 23);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 5, 10, 24);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 6, 8453, 30);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 7, 999, 47);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 8, 143, 48);
    }

    function _setWormholeConfigAt(
        Universe[] memory universes,
        uint256[] memory chainIds,
        uint16[] memory wormholeChainIds,
        uint256 index,
        uint256 chainId,
        uint16 wormholeChainId
    ) internal pure {
        universes[index] = Universe.ETHEREUM;
        chainIds[index] = chainId;
        wormholeChainIds[index] = wormholeChainId;
    }

    function _setNativeTokenDecimals(
        uint16[] memory tokenWormholeChainIds,
        address[] memory tokens,
        uint8[] memory decimals
    ) internal pure {
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 0, 2, address(0), 18);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 1, 2, 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2, 18);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 2, 4, address(0), 18);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 3, 4, 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c, 18);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 4, 5, address(0), 18);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 5, 5, 0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270, 18);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 6, 6, address(0), 18);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 7, 6, 0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7, 18);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 8, 23, address(0), 18);
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 9, 23, 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1, 18
        );
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 10, 24, address(0), 18);
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 11, 24, 0x4200000000000000000000000000000000000006, 18
        );
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 12, 30, address(0), 18);
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 13, 30, 0x4200000000000000000000000000000000000006, 18
        );
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 14, 47, address(0), 18);
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 15, 47, 0x5555555555555555555555555555555555555555, 18
        );
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 16, 48, address(0), 18);
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 17, 48, 0x3bd359C1119dA7Da1D913D1C4D2B7c461115433A, 18
        );
    }

    function _setUsdcTokenDecimals(
        uint16[] memory tokenWormholeChainIds,
        address[] memory tokens,
        uint8[] memory decimals
    ) internal pure {
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 18, 2, 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, 6);
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 19, 4, 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d, 18
        );
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 20, 5, 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359, 6);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 21, 6, 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E, 6);
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 22, 23, 0xaf88d065e77c8cC2239327C5EDb3A432268e5831, 6
        );
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 23, 24, 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85, 6
        );
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 24, 30, 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913, 6
        );
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 25, 47, 0xb88339CB7199b77E23DB6E890353E22632Ba630f, 6
        );
        _setTokenDecimals(
            tokenWormholeChainIds, tokens, decimals, 26, 48, 0x754704Bc059F8C67012fEd69BC8A327a5aafb603, 6
        );
    }

    function _setTokenDecimals(
        uint16[] memory tokenWormholeChainIds,
        address[] memory tokens,
        uint8[] memory decimals,
        uint256 index,
        uint16 wormholeChainId,
        address token,
        uint8 tokenDecimals
    ) internal pure {
        tokenWormholeChainIds[index] = wormholeChainId;
        tokens[index] = token;
        decimals[index] = tokenDecimals;
    }
}
