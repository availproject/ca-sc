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

        Universe[] memory universes = new Universe[](0);
        uint256[] memory chainIds = new uint256[](0);
        uint16[] memory wormholeChainIds = new uint16[](0);
        uint16[] memory tokenWormholeChainIds = new uint16[](0);
        address[] memory tokens = new address[](0);
        uint8[] memory decimals = new uint8[](0);
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
