// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";
import {Upgrades, Options} from "openzeppelin-foundry-upgrades/Upgrades.sol";
import {Vault} from "../src/Vault.sol";

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address);
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address);
}

interface IVault {
    function hasRole(bytes32 role, address account) external view returns (bool);
    function grantRole(bytes32 role, address account) external;
    function upgradeToAndCall(address newImplementation, bytes memory data) external;
}

interface IERC1822Proxiable {
    function proxiableUUID() external view returns (bytes32);
}

contract UpgradeVault is Script {
    address public constant DEFAULT_PROXY_ADDRESS = 0x86B60E813f9b739516dDbDc443526be5Ef8336aa;
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    ICreateX public constant CREATEX = ICreateX(0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed);
    string public constant VAULT_CONTRACT = "Vault.sol:Vault";
    string public constant DEFAULT_REFERENCE_CONTRACT = "VaultOld.sol:VaultOld";

    // function run(address proxyAddress, bytes32 salt) external {
    //     _upgrade(proxyAddress, salt);
    // }
    //
    // function run(address proxyAddress) external {
    //     bytes32 salt = keccak256(abi.encodePacked("upgrade", block.timestamp, proxyAddress));
    //     _upgrade(proxyAddress, salt);
    // }

    function run() external {
        address proxyAddress = vm.envOr("PROXY_ADDRESS", DEFAULT_PROXY_ADDRESS);
        bytes32 salt;
        try vm.envBytes32("UPGRADE_SALT") returns (bytes32 envSalt) {
            salt = envSalt;
        } catch {
            salt = keccak256(abi.encodePacked("upgrade", block.timestamp, proxyAddress));
        }
        _upgrade(proxyAddress, salt);
    }

    function _upgrade(address proxyAddress, bytes32 salt) internal {
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

        address currentImpl = getImplementation(proxyAddress);
        console.log("Current Implementation:", currentImpl);
        require(proxyAddress.code.length > 0, "UpgradeVault: proxy has no code");
        require(currentImpl != address(0), "UpgradeVault: proxy implementation not set");
        require(currentImpl.code.length > 0, "UpgradeVault: implementation has no code");

        bytes memory vaultInitCode = type(Vault).creationCode;
        bytes32 vaultInitCodeHash = keccak256(vaultInitCode);
        address expectedImpl = CREATEX.computeCreate2Address(salt, vaultInitCodeHash);
        console.log("Expected New Implementation:", expectedImpl);

        IVault proxy = IVault(proxyAddress);
        bool hasUpgraderRole = proxy.hasRole(UPGRADER_ROLE, deployer);
        bool hasAdminRole = proxy.hasRole(DEFAULT_ADMIN_ROLE, deployer);
        console.log("Has UPGRADER_ROLE:", hasUpgraderRole);
        console.log("Has DEFAULT_ADMIN_ROLE:", hasAdminRole);

        if (!hasUpgraderRole) {
            require(hasAdminRole, "UpgradeVault: caller has neither admin nor upgrader role");

            console.log("Deployer has admin role. Granting UPGRADER_ROLE...");
            proxy.grantRole(UPGRADER_ROLE, deployer);
            require(proxy.hasRole(UPGRADER_ROLE, deployer), "UpgradeVault: failed to grant UPGRADER_ROLE");
            console.log("UPGRADER_ROLE granted");
        }

        address newImplementation = CREATEX.deployCreate2(salt, vaultInitCode);
        console.log("New Implementation:", newImplementation);
        require(newImplementation == expectedImpl, "Implementation address mismatch");
        require(
            IERC1822Proxiable(newImplementation).proxiableUUID() == ERC1967_IMPLEMENTATION_SLOT,
            "UpgradeVault: invalid UUPS implementation"
        );

        proxy.upgradeToAndCall(newImplementation, "");
        console.log("Proxy upgraded");

        vm.stopBroadcast();

        address verifiedImpl = getImplementation(proxyAddress);
        console.log("\n=== UPGRADE COMPLETE ===");
        console.log("Old Implementation:", currentImpl);
        console.log("New Implementation:", verifiedImpl);
        require(verifiedImpl == newImplementation, "Upgrade verification failed");
        console.log("Upgrade verified");
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

    function validateUpgradeSafety() external {
        _validateUpgradeSafety();
    }

    function preview(address proxyAddress, bytes32 salt) external view returns (address newImpl) {
        console.log("Proxy:", proxyAddress);
        console.log("Salt:", vm.toString(salt));

        newImpl = CREATEX.computeCreate2Address(salt, keccak256(type(Vault).creationCode));
        console.log("Expected New Implementation:", newImpl);

        address currentImpl = getImplementation(proxyAddress);
        console.log("Current Implementation:", currentImpl);
    }

    function getImplementation(address proxy) internal view returns (address) {
        bytes32 implBytes = vm.load(proxy, ERC1967_IMPLEMENTATION_SLOT);
        return address(uint160(uint256(implBytes)));
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
