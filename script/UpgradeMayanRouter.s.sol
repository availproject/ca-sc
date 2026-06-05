// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {MayanRouter} from "../src/routes/mayan.sol";
import {Universe} from "../src/types.sol";

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address);
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address);
}

interface IMayanRouterUpgrade {
    function hasRole(bytes32 role, address account) external view returns (bool);
    function grantRole(bytes32 role, address account) external;
    function setWormholeChainMapping(Universe universe, uint256 chainId, uint16 wormholeChainId) external;
    function setTokenOutDecimals(uint16 wormholeChainId, address token, uint8 decimals) external;
    function upgradeToAndCall(address newImplementation, bytes memory data) external;
}

interface IERC1822Proxiable {
    function proxiableUUID() external view returns (bytes32);
}

/// @title UpgradeMayanRouter
/// @notice Deploys a new MayanRouter implementation via CreateX and upgrades the UUPS proxy.
contract UpgradeMayanRouter is Script {
    address public constant DEFAULT_PROXY_ADDRESS = 0x1F035f26710d5a3C4F7052f184564C8e4707c8f1;
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    ICreateX public constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);

    uint8 public constant WRAPPED_NATIVE_DECIMALS = 18;
    uint8 public constant USDC_DECIMALS = 6;
    uint8 public constant BSC_USDC_DECIMALS = 18;

    uint16 public constant ETHEREUM_WORMHOLE_CHAIN_ID = 2;
    uint16 public constant BSC_WORMHOLE_CHAIN_ID = 4;
    uint16 public constant POLYGON_WORMHOLE_CHAIN_ID = 5;
    uint16 public constant AVALANCHE_WORMHOLE_CHAIN_ID = 6;
    uint16 public constant ARBITRUM_WORMHOLE_CHAIN_ID = 23;
    uint16 public constant OPTIMISM_WORMHOLE_CHAIN_ID = 24;
    uint16 public constant BASE_WORMHOLE_CHAIN_ID = 30;
    uint256 public constant HYPEREVM_CHAIN_ID = 999;
    uint256 public constant MONAD_CHAIN_ID = 143;
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

    function run() external {
        address proxyAddress = vm.envOr("MAYAN_ROUTER_PROXY_ADDRESS", DEFAULT_PROXY_ADDRESS);
        bytes32 salt;
        try vm.envBytes32("MAYAN_ROUTER_UPGRADE_SALT") returns (bytes32 envSalt) {
            salt = envSalt;
        } catch {
            salt = keccak256(abi.encodePacked("mayan-router-upgrade", proxyAddress));
        }

        _upgrade(proxyAddress, salt);
    }

    function preview(address proxyAddress, bytes32 salt) external view returns (address newImpl) {
        console.log("Proxy:", proxyAddress);
        console.log("Salt:", vm.toString(salt));

        newImpl = CREATEX.computeCreate2Address(_createXComputeSalt(salt), keccak256(type(MayanRouter).creationCode));
        console.log("Expected New Implementation:", newImpl);

        address currentImpl = getImplementation(proxyAddress);
        console.log("Current Implementation:", currentImpl);
    }

    function _upgrade(address proxyAddress, bytes32 salt) internal {
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

        address currentImpl = getImplementation(proxyAddress);
        console.log("Current Implementation:", currentImpl);
        require(proxyAddress.code.length > 0, "UpgradeMayanRouter: proxy has no code");
        require(currentImpl != address(0), "UpgradeMayanRouter: proxy implementation not set");
        require(currentImpl.code.length > 0, "UpgradeMayanRouter: implementation has no code");

        bytes memory routerInitCode = type(MayanRouter).creationCode;
        address expectedImpl = CREATEX.computeCreate2Address(_createXComputeSalt(salt), keccak256(routerInitCode));
        console.log("Expected New Implementation:", expectedImpl);

        IMayanRouterUpgrade proxy = IMayanRouterUpgrade(proxyAddress);
        bool hasUpgraderRole = proxy.hasRole(UPGRADER_ROLE, deployer);
        bool hasAdminRole = proxy.hasRole(DEFAULT_ADMIN_ROLE, deployer);
        console.log("Has UPGRADER_ROLE:", hasUpgraderRole);
        console.log("Has DEFAULT_ADMIN_ROLE:", hasAdminRole);

        if (!hasUpgraderRole) {
            require(hasAdminRole, "UpgradeMayanRouter: caller has neither admin nor upgrader role");

            console.log("Deployer has admin role. Granting UPGRADER_ROLE...");
            proxy.grantRole(UPGRADER_ROLE, deployer);
            require(proxy.hasRole(UPGRADER_ROLE, deployer), "UpgradeMayanRouter: failed to grant UPGRADER_ROLE");
            console.log("UPGRADER_ROLE granted");
        }

        address newImplementation = expectedImpl;
        if (newImplementation.code.length == 0) {
            newImplementation = CREATEX.deployCreate2(salt, routerInitCode);
            console.log("New Implementation Deployed:", newImplementation);
        } else {
            console.log("New Implementation Already Deployed:", newImplementation);
        }

        require(newImplementation == expectedImpl, "UpgradeMayanRouter: implementation address mismatch");
        require(
            IERC1822Proxiable(newImplementation).proxiableUUID() == ERC1967_IMPLEMENTATION_SLOT,
            "UpgradeMayanRouter: invalid UUPS implementation"
        );

        proxy.upgradeToAndCall(newImplementation, "");
        console.log("Proxy upgraded");

        // _setWormholeChainMappings(proxy);
        // _setWrappedNativeTokenDecimals(proxy);
        // _setUsdcTokenDecimals(proxy);

        vm.stopBroadcast();

        address verifiedImpl = getImplementation(proxyAddress);
        console.log("\n=== MAYAN ROUTER UPGRADE COMPLETE ===");
        console.log("Old Implementation:", currentImpl);
        console.log("New Implementation:", verifiedImpl);
        require(verifiedImpl == newImplementation, "UpgradeMayanRouter: upgrade verification failed");
        console.log("Upgrade verified");
    }

    function _setWormholeChainMappings(IMayanRouterUpgrade proxy) internal {
        console.log("\n========== Setting Ethereum Universe Wormhole Chain Mappings ==========");
        _setWormholeChainMapping(proxy, MONAD_CHAIN_ID, MONAD_WORMHOLE_CHAIN_ID, "Monad");
        _setWormholeChainMapping(proxy, HYPEREVM_CHAIN_ID, HYPEREVM_WORMHOLE_CHAIN_ID, "HyperEVM");
    }

    function _setWormholeChainMapping(
        IMayanRouterUpgrade proxy,
        uint256 chainId,
        uint16 wormholeChainId,
        string memory networkName
    ) internal {
        proxy.setWormholeChainMapping(Universe.ETHEREUM, chainId, wormholeChainId);
        console.log(networkName, "chain ID:", chainId);
        console.log(networkName, "Wormhole chain ID:", wormholeChainId);
    }

    function _setWrappedNativeTokenDecimals(IMayanRouterUpgrade proxy) internal {
        console.log("\n========== Setting Wrapped Native Token Decimals ==========");
        _setNativeTokenDecimals(proxy, ETHEREUM_WORMHOLE_CHAIN_ID, ETHEREUM_WETH, "Ethereum WETH");
        _setNativeTokenDecimals(proxy, BSC_WORMHOLE_CHAIN_ID, BSC_WBNB, "BSC WBNB");
        _setNativeTokenDecimals(proxy, POLYGON_WORMHOLE_CHAIN_ID, POLYGON_WPOL, "Polygon WPOL");
        _setNativeTokenDecimals(proxy, AVALANCHE_WORMHOLE_CHAIN_ID, AVALANCHE_WAVAX, "Avalanche WAVAX");
        _setNativeTokenDecimals(proxy, ARBITRUM_WORMHOLE_CHAIN_ID, ARBITRUM_WETH, "Arbitrum WETH");
        _setNativeTokenDecimals(proxy, OPTIMISM_WORMHOLE_CHAIN_ID, OPTIMISM_WETH, "Optimism WETH");
        _setNativeTokenDecimals(proxy, BASE_WORMHOLE_CHAIN_ID, BASE_WETH, "Base WETH");
        _setNativeTokenDecimals(proxy, HYPEREVM_WORMHOLE_CHAIN_ID, HYPEREVM_WHYPE, "HyperEVM WHYPE");
        _setNativeTokenDecimals(proxy, MONAD_WORMHOLE_CHAIN_ID, MONAD_WMON, "Monad WMON");
    }

    function _setNativeTokenDecimals(
        IMayanRouterUpgrade proxy,
        uint16 wormholeChainId,
        address wrappedNative,
        string memory tokenName
    ) internal {
        proxy.setTokenOutDecimals(wormholeChainId, address(0), WRAPPED_NATIVE_DECIMALS);
        proxy.setTokenOutDecimals(wormholeChainId, wrappedNative, WRAPPED_NATIVE_DECIMALS);

        console.log(tokenName, "Wormhole chain ID:", wormholeChainId);
        console.log(tokenName, "wrapped token:", wrappedNative);
        console.log(tokenName, "decimals:", WRAPPED_NATIVE_DECIMALS);
    }

    function _setUsdcTokenDecimals(IMayanRouterUpgrade proxy) internal {
        console.log("\n========== Setting USDC Token Decimals ==========");
        _setTokenDecimals(proxy, ETHEREUM_WORMHOLE_CHAIN_ID, ETHEREUM_USDC, USDC_DECIMALS, "Ethereum USDC");
        _setTokenDecimals(proxy, BSC_WORMHOLE_CHAIN_ID, BSC_BINANCE_PEG_USDC, BSC_USDC_DECIMALS, "BSC Binance-Peg USDC");
        _setTokenDecimals(proxy, POLYGON_WORMHOLE_CHAIN_ID, POLYGON_USDC, USDC_DECIMALS, "Polygon USDC");
        _setTokenDecimals(proxy, AVALANCHE_WORMHOLE_CHAIN_ID, AVALANCHE_USDC, USDC_DECIMALS, "Avalanche USDC");
        _setTokenDecimals(proxy, ARBITRUM_WORMHOLE_CHAIN_ID, ARBITRUM_USDC, USDC_DECIMALS, "Arbitrum USDC");
        _setTokenDecimals(proxy, OPTIMISM_WORMHOLE_CHAIN_ID, OPTIMISM_USDC, USDC_DECIMALS, "Optimism USDC");
        _setTokenDecimals(proxy, BASE_WORMHOLE_CHAIN_ID, BASE_USDC, USDC_DECIMALS, "Base USDC");
        _setTokenDecimals(proxy, HYPEREVM_WORMHOLE_CHAIN_ID, HYPEREVM_USDC, USDC_DECIMALS, "HyperEVM USDC");
        _setTokenDecimals(proxy, MONAD_WORMHOLE_CHAIN_ID, MONAD_USDC, USDC_DECIMALS, "Monad USDC");
    }

    function _setTokenDecimals(
        IMayanRouterUpgrade proxy,
        uint16 wormholeChainId,
        address token,
        uint8 decimals,
        string memory tokenName
    ) internal {
        proxy.setTokenOutDecimals(wormholeChainId, token, decimals);

        console.log(tokenName, "Wormhole chain ID:", wormholeChainId);
        console.log(tokenName, "token:", token);
        console.log(tokenName, "decimals:", decimals);
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

    function _createXComputeSalt(bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(salt));
    }

    function getImplementation(address proxy) internal view returns (address) {
        bytes32 implBytes = vm.load(proxy, ERC1967_IMPLEMENTATION_SLOT);
        return address(uint160(uint256(implBytes)));
    }
}
