// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Upgrades, Options} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Vault} from "../src/Vault.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {Universe} from "../src/types.sol";

interface ICreateXSafeUpgrade {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address);
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address);
}

interface IVaultSafeUpgrade {
    function upgradeToAndCall(address newImplementation, bytes memory data) external;
    function setRouter(address _router) external;
}

interface IMayanRouterSafeSetup {
    function grantRole(bytes32 role, address account) external;
}

interface IERC1822ProxiableSafeUpgrade {
    function proxiableUUID() external view returns (bytes32);
}

/// @title DeployVaultImplementationForSafe
/// @notice Deploys a new Vault implementation and prints the Safe transaction calldata.
contract DeployVaultImplementationForSafe is Script {
    address public constant DEFAULT_PROXY_ADDRESS = 0x86B60E813f9b739516dDbDc443526be5Ef8336aa;
    bytes32 public constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    ICreateXSafeUpgrade public constant CREATEX = ICreateXSafeUpgrade(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);
    string public constant VAULT_CONTRACT = "Vault.sol:Vault";
    string public constant DEFAULT_REFERENCE_CONTRACT = "VaultOld.sol:VaultOld";

    uint8 public constant WRAPPED_NATIVE_DECIMALS = 18;
    uint8 public constant USDC_DECIMALS = 6;
    uint8 public constant BSC_USDC_DECIMALS = 18;
    uint8 public constant USDT_DECIMALS = 6;
    uint8 public constant BSC_USDT_DECIMALS = 18;

    uint256 public constant ETHEREUM_CHAIN_ID = 1;
    uint256 public constant BSC_CHAIN_ID = 56;
    uint256 public constant POLYGON_CHAIN_ID = 137;
    uint256 public constant AVALANCHE_CHAIN_ID = 43_114;
    uint256 public constant ARBITRUM_CHAIN_ID = 42_161;
    uint256 public constant OPTIMISM_CHAIN_ID = 10;
    uint256 public constant BASE_CHAIN_ID = 8453;
    uint256 public constant HYPEREVM_CHAIN_ID = 999;
    uint256 public constant MONAD_CHAIN_ID = 143;

    uint16 public constant ETHEREUM_WORMHOLE_CHAIN_ID = 2;
    uint16 public constant BSC_WORMHOLE_CHAIN_ID = 4;
    uint16 public constant POLYGON_WORMHOLE_CHAIN_ID = 5;
    uint16 public constant AVALANCHE_WORMHOLE_CHAIN_ID = 6;
    uint16 public constant ARBITRUM_WORMHOLE_CHAIN_ID = 23;
    uint16 public constant OPTIMISM_WORMHOLE_CHAIN_ID = 24;
    uint16 public constant BASE_WORMHOLE_CHAIN_ID = 30;
    uint16 public constant HYPEREVM_WORMHOLE_CHAIN_ID = 47;
    uint16 public constant MONAD_WORMHOLE_CHAIN_ID = 48;

    address public constant ETHEREUM_WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address public constant BSC_WBNB = 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c;
    address public constant POLYGON_WPOL = 0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270;
    address public constant AVALANCHE_WAVAX = 0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7;
    address public constant ARBITRUM_WETH = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1;
    address public constant OPTIMISM_WETH = 0x4200000000000000000000000000000000000006;
    address public constant BASE_WETH = 0x4200000000000000000000000000000000000006;
    address public constant HYPEREVM_WHYPE = 0x5555555555555555555555555555555555555555;
    address public constant MONAD_WMON = 0x3bd359C1119dA7Da1D913D1C4D2B7c461115433A;

    address public constant ETHEREUM_USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public constant BSC_BINANCE_PEG_USDC = 0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d;
    address public constant POLYGON_USDC = 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359;
    address public constant AVALANCHE_USDC = 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E;
    address public constant ARBITRUM_USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831;
    address public constant OPTIMISM_USDC = 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85;
    address public constant BASE_USDC = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;
    address public constant HYPEREVM_USDC = 0xb88339CB7199b77E23DB6E890353E22632Ba630f;
    address public constant MONAD_USDC = 0x754704Bc059F8C67012fEd69BC8A327a5aafb603;

    address public constant ETHEREUM_USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    address public constant BSC_USDT = 0x55d398326f99059fF775485246999027B3197955;
    address public constant POLYGON_USDT = 0xc2132D05D31c914a87C6611C10748AEb04B58e8F;
    address public constant AVALANCHE_USDT = 0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7;
    address public constant ARBITRUM_USDT = 0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9;
    address public constant OPTIMISM_USDT = 0x94b008aA00579c1307B0EF2c499aD98a8ce58e58;
    address public constant BASE_USDT = 0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2;
    address public constant HYPEREVM_USDT = 0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb;
    address public constant MONAD_USDT = 0xe7cd86e13AC4309349F30B3435a9d337750fC82D;

    function run() external {
        address proxyAddress = vm.envOr("PROXY_ADDRESS", DEFAULT_PROXY_ADDRESS);
        bytes32 salt;
        try vm.envBytes32("UPGRADE_SALT") returns (bytes32 envSalt) {
            salt = envSalt;
        } catch {
            salt = keccak256(abi.encodePacked("upgrade", proxyAddress));
        }

        _deployImplementationAndRouterAndPrintSafeCalldata(proxyAddress, salt);
    }

    function _deployImplementationAndRouterAndPrintSafeCalldata(address proxyAddress, bytes32 salt) internal {
        _validateUpgradeSafety();

        address deployer;
        try vm.envUint("PRIVATE_KEY") returns (uint256 deployerPrivateKey) {
            deployer = vm.addr(deployerPrivateKey);
            vm.startBroadcast(deployerPrivateKey);
        } catch {
            deployer = _broadcastSender();
            vm.startBroadcast(deployer);
        }

        console.log("Deployer:", deployer);
        console.log("Proxy:", proxyAddress);
        console.log("Salt:", vm.toString(salt));
        address routerAdmin = _routerAdmin(deployer);
        console.log("MayanRouter Admin:", routerAdmin);

        require(proxyAddress.code.length > 0, "SafeUpgradeVault: proxy has no code");
        address currentImpl = getImplementation(proxyAddress);
        console.log("Current Implementation:", currentImpl);
        require(currentImpl != address(0), "SafeUpgradeVault: proxy implementation not set");
        require(currentImpl.code.length > 0, "SafeUpgradeVault: implementation has no code");

        bytes memory vaultInitCode = type(Vault).creationCode;
        bytes32 vaultInitCodeHash = keccak256(vaultInitCode);
        address expectedImpl = CREATEX.computeCreate2Address(_createXComputeSalt(salt), vaultInitCodeHash);
        console.log("Expected New Implementation:", expectedImpl);

        address newImplementation = expectedImpl;
        if (newImplementation.code.length == 0) {
            newImplementation = CREATEX.deployCreate2(salt, vaultInitCode);
            console.log("New Implementation Deployed:", newImplementation);
        } else {
            console.log("New Implementation Already Deployed:", newImplementation);
        }

        require(
            IERC1822ProxiableSafeUpgrade(newImplementation).proxiableUUID() == ERC1967_IMPLEMENTATION_SLOT,
            "SafeUpgradeVault: invalid UUPS implementation"
        );

        address mayanRouter = _deployMayanRouter(salt, routerAdmin);

        vm.stopBroadcast();

        bytes memory safeCalldata = abi.encodeCall(IVaultSafeUpgrade.upgradeToAndCall, (newImplementation, bytes("")));
        bytes memory setRouterCalldata = abi.encodeCall(IVaultSafeUpgrade.setRouter, (mayanRouter));
        bytes memory grantVaultRoleCalldata =
            abi.encodeCall(IMayanRouterSafeSetup.grantRole, (MayanRouter(mayanRouter).VAULT_ROLE(), proxyAddress));

        console.log("\n=== GNOSIS SAFE TRANSACTION ===");
        console.log("To:", proxyAddress);
        console.log("Value:", uint256(0));
        console.log("Method: upgradeToAndCall(address,bytes)");
        console.log("New Implementation:", newImplementation);
        console.log("Data:");
        console.logBytes(safeCalldata);
        console.log("\nAfter execution, proxy implementation should be:", newImplementation);

        console.log("\n=== GNOSIS SAFE TRANSACTION: SET VAULT ROUTER ===");
        console.log("To:", proxyAddress);
        console.log("Value:", uint256(0));
        console.log("Method: setRouter(address)");
        console.log("MayanRouter:", mayanRouter);
        console.log("Data:");
        console.logBytes(setRouterCalldata);

        console.log("\n=== ROUTER ADMIN TRANSACTION: GRANT VAULT_ROLE ===");
        console.log("To:", mayanRouter);
        console.log("Value:", uint256(0));
        console.log("Method: grantRole(bytes32,address)");
        console.log("Role VAULT_ROLE:", vm.toString(MayanRouter(mayanRouter).VAULT_ROLE()));
        console.log("Account:", proxyAddress);
        console.log("Data:");
        console.logBytes(grantVaultRoleCalldata);
        console.log("\nExecute this from the MayanRouter admin:", routerAdmin);
    }

    function preview(address proxyAddress, bytes32 salt)
        external
        view
        returns (address newImpl, bytes memory safeCalldata)
    {
        newImpl = CREATEX.computeCreate2Address(_createXComputeSalt(salt), keccak256(type(Vault).creationCode));
        safeCalldata = abi.encodeCall(IVaultSafeUpgrade.upgradeToAndCall, (newImpl, bytes("")));

        console.log("Proxy:", proxyAddress);
        console.log("Salt:", vm.toString(salt));
        console.log("Current Implementation:", getImplementation(proxyAddress));
        console.log("Expected New Implementation:", newImpl);
        console.log("Safe To:", proxyAddress);
        console.log("Safe Value:", uint256(0));
        console.log("Safe Data:");
        console.logBytes(safeCalldata);
    }

    function _deployMayanRouter(bytes32 salt, address routerAdmin) internal returns (address mayanRouter) {
        bytes32 mayanSalt = _envOrSalt("MAYAN_ROUTER_SALT", keccak256(abi.encodePacked(salt, "mayan-router")));
        bytes32 mayanProxySalt = _envOrSalt("MAYAN_ROUTER_PROXY_SALT", keccak256(abi.encodePacked(mayanSalt, "proxy")));

        console.log("\n========== Deploying MayanRouter ==========");
        console.log("MayanRouter Salt:", vm.toString(mayanSalt));
        console.log("MayanRouter Proxy Salt:", vm.toString(mayanProxySalt));

        bytes memory mayanInitCode = type(MayanRouter).creationCode;
        address expectedMayanImpl =
            CREATEX.computeCreate2Address(_createXComputeSalt(mayanSalt), keccak256(mayanInitCode));
        console.log("Expected MayanRouter Implementation:", expectedMayanImpl);

        address mayanImplementation = expectedMayanImpl;
        if (mayanImplementation.code.length == 0) {
            mayanImplementation = CREATEX.deployCreate2(mayanSalt, mayanInitCode);
            console.log("MayanRouter Implementation Deployed:", mayanImplementation);
        } else {
            console.log("MayanRouter Implementation Already Deployed:", mayanImplementation);
        }

        require(
            IERC1822ProxiableSafeUpgrade(mayanImplementation).proxiableUUID() == ERC1967_IMPLEMENTATION_SLOT,
            "SafeUpgradeVault: invalid MayanRouter UUPS implementation"
        );

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
            routerAdmin,
            universes,
            chainIds,
            wormholeChainIds,
            tokenWormholeChainIds,
            tokens,
            decimals
        );
        bytes memory mayanProxyInitCode =
            abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(mayanImplementation, mayanRouterInitData));
        mayanRouter = CREATEX.computeCreate2Address(_createXComputeSalt(mayanProxySalt), keccak256(mayanProxyInitCode));
        console.log("Expected MayanRouter Proxy:", mayanRouter);

        if (mayanRouter.code.length == 0) {
            address deployedMayanRouter = CREATEX.deployCreate2(mayanProxySalt, mayanProxyInitCode);
            console.log("MayanRouter Proxy Deployed:", deployedMayanRouter);
            require(deployedMayanRouter == mayanRouter, "SafeUpgradeVault: MayanRouter proxy address mismatch");
        } else {
            console.log("MayanRouter Proxy Already Deployed:", mayanRouter);
        }
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

        tokenWormholeChainIds = new uint16[](36);
        tokens = new address[](36);
        decimals = new uint8[](36);

        _setNativeTokenDecimals(tokenWormholeChainIds, tokens, decimals);
        _setUsdcTokenDecimals(tokenWormholeChainIds, tokens, decimals);
        _setUsdtTokenDecimals(tokenWormholeChainIds, tokens, decimals);
    }

    function _setWormholeConfig(
        Universe[] memory universes,
        uint256[] memory chainIds,
        uint16[] memory wormholeChainIds
    ) internal pure {
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 0, ETHEREUM_CHAIN_ID, ETHEREUM_WORMHOLE_CHAIN_ID);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 1, BSC_CHAIN_ID, BSC_WORMHOLE_CHAIN_ID);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 2, POLYGON_CHAIN_ID, POLYGON_WORMHOLE_CHAIN_ID);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 3, AVALANCHE_CHAIN_ID, AVALANCHE_WORMHOLE_CHAIN_ID);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 4, ARBITRUM_CHAIN_ID, ARBITRUM_WORMHOLE_CHAIN_ID);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 5, OPTIMISM_CHAIN_ID, OPTIMISM_WORMHOLE_CHAIN_ID);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 6, BASE_CHAIN_ID, BASE_WORMHOLE_CHAIN_ID);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 7, HYPEREVM_CHAIN_ID, HYPEREVM_WORMHOLE_CHAIN_ID);
        _setWormholeConfigAt(universes, chainIds, wormholeChainIds, 8, MONAD_CHAIN_ID, MONAD_WORMHOLE_CHAIN_ID);
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
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 0, ETHEREUM_WORMHOLE_CHAIN_ID, address(0), WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 1, ETHEREUM_WORMHOLE_CHAIN_ID, ETHEREUM_WETH, WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 2, BSC_WORMHOLE_CHAIN_ID, address(0), WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 3, BSC_WORMHOLE_CHAIN_ID, BSC_WBNB, WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 4, POLYGON_WORMHOLE_CHAIN_ID, address(0), WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 5, POLYGON_WORMHOLE_CHAIN_ID, POLYGON_WPOL, WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 6, AVALANCHE_WORMHOLE_CHAIN_ID, address(0), WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 7, AVALANCHE_WORMHOLE_CHAIN_ID, AVALANCHE_WAVAX, WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 8, ARBITRUM_WORMHOLE_CHAIN_ID, address(0), WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 9, ARBITRUM_WORMHOLE_CHAIN_ID, ARBITRUM_WETH, WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 10, OPTIMISM_WORMHOLE_CHAIN_ID, address(0), WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 11, OPTIMISM_WORMHOLE_CHAIN_ID, OPTIMISM_WETH, WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 12, BASE_WORMHOLE_CHAIN_ID, address(0), WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 13, BASE_WORMHOLE_CHAIN_ID, BASE_WETH, WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 14, HYPEREVM_WORMHOLE_CHAIN_ID, address(0), WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 15, HYPEREVM_WORMHOLE_CHAIN_ID, HYPEREVM_WHYPE, WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 16, MONAD_WORMHOLE_CHAIN_ID, address(0), WRAPPED_NATIVE_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 17, MONAD_WORMHOLE_CHAIN_ID, MONAD_WMON, WRAPPED_NATIVE_DECIMALS);
    }

    function _setUsdcTokenDecimals(
        uint16[] memory tokenWormholeChainIds,
        address[] memory tokens,
        uint8[] memory decimals
    ) internal pure {
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 18, ETHEREUM_WORMHOLE_CHAIN_ID, ETHEREUM_USDC, USDC_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 19, BSC_WORMHOLE_CHAIN_ID, BSC_BINANCE_PEG_USDC, BSC_USDC_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 20, POLYGON_WORMHOLE_CHAIN_ID, POLYGON_USDC, USDC_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 21, AVALANCHE_WORMHOLE_CHAIN_ID, AVALANCHE_USDC, USDC_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 22, ARBITRUM_WORMHOLE_CHAIN_ID, ARBITRUM_USDC, USDC_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 23, OPTIMISM_WORMHOLE_CHAIN_ID, OPTIMISM_USDC, USDC_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 24, BASE_WORMHOLE_CHAIN_ID, BASE_USDC, USDC_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 25, HYPEREVM_WORMHOLE_CHAIN_ID, HYPEREVM_USDC, USDC_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 26, MONAD_WORMHOLE_CHAIN_ID, MONAD_USDC, USDC_DECIMALS);
    }

    function _setUsdtTokenDecimals(
        uint16[] memory tokenWormholeChainIds,
        address[] memory tokens,
        uint8[] memory decimals
    ) internal pure {
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 27, ETHEREUM_WORMHOLE_CHAIN_ID, ETHEREUM_USDT, USDT_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 28, BSC_WORMHOLE_CHAIN_ID, BSC_USDT, BSC_USDT_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 29, POLYGON_WORMHOLE_CHAIN_ID, POLYGON_USDT, USDT_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 30, AVALANCHE_WORMHOLE_CHAIN_ID, AVALANCHE_USDT, USDT_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 31, ARBITRUM_WORMHOLE_CHAIN_ID, ARBITRUM_USDT, USDT_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 32, OPTIMISM_WORMHOLE_CHAIN_ID, OPTIMISM_USDT, USDT_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 33, BASE_WORMHOLE_CHAIN_ID, BASE_USDT, USDT_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 34, HYPEREVM_WORMHOLE_CHAIN_ID, HYPEREVM_USDT, USDT_DECIMALS);
        _setTokenDecimals(tokenWormholeChainIds, tokens, decimals, 35, MONAD_WORMHOLE_CHAIN_ID, MONAD_USDT, USDT_DECIMALS);
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

    function _createXComputeSalt(bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(salt));
    }

    function _envOrSalt(string memory key, bytes32 defaultSalt) internal view returns (bytes32) {
        try vm.envBytes32(key) returns (bytes32 envSalt) {
            return envSalt;
        } catch {
            return defaultSalt;
        }
    }

    function getImplementation(address proxy) internal view returns (address) {
        bytes32 implBytes = vm.load(proxy, ERC1967_IMPLEMENTATION_SLOT);
        return address(uint160(uint256(implBytes)));
    }

    function _broadcastSender() internal view returns (address) {
        try vm.envAddress("SENDER") returns (address sender) {
            return sender;
        } catch {}
        try vm.envAddress("BROADCASTER") returns (address broadcaster) {
            return broadcaster;
        } catch {}
        try vm.envAddress("ADMIN") returns (address admin) {
            return admin;
        } catch {}

        return msg.sender;
    }

    function _routerAdmin(address deployer) internal view returns (address) {
        try vm.envAddress("SAFE_ADDRESS") returns (address safeAddress) {
            return safeAddress;
        } catch {}
        try vm.envAddress("ADMIN_ADDRESS") returns (address adminAddress) {
            return adminAddress;
        } catch {}
        try vm.envAddress("ADMIN") returns (address admin) {
            return admin;
        } catch {}

        return deployer;
    }

    function _validateUpgradeSafety() internal {
        Options memory opts;
        opts.referenceContract = DEFAULT_REFERENCE_CONTRACT;
        try vm.envString("REFERENCE_CONTRACT") returns (string memory referenceContract) {
            opts.referenceContract = referenceContract;
        } catch {}
        try vm.envString("REFERENCE_BUILD_INFO_DIR") returns (string memory referenceBuildInfoDir) {
            opts.referenceBuildInfoDir = referenceBuildInfoDir;
        } catch {}

        console.log("Checking OpenZeppelin upgrade safety for:", VAULT_CONTRACT);
        if (bytes(opts.referenceContract).length > 0) {
            console.log("Reference Contract:", opts.referenceContract);
        }
        if (bytes(opts.referenceBuildInfoDir).length > 0) {
            console.log("Reference Build Info Dir:", opts.referenceBuildInfoDir);
        }
        Upgrades.validateUpgrade(VAULT_CONTRACT, opts);
        console.log("OpenZeppelin upgrade safety check passed");
    }
}
