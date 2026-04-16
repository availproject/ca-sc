// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.0;

/**
 * @title CreateX Factory Interface
 * @author pcaversaccio
 * @dev Interface for the CreateX factory contract at 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed
 * @notice A permissionless CREATE2/CREATE3 factory with guardrails for cross-chain deployment
 */
interface ICreateX {
    /**
     * @dev Emitted when a contract is created using the CREATE2 opcode.
     * @param newContract The address of the newly created contract.
     * @param salt The 32-byte random value used to create the contract address.
     */
    event ContractCreation(address indexed newContract, bytes32 indexed salt);

    /**
     * @dev Emitted when a contract is created using the CREATE3 opcode.
     * @param newContract The address of the newly created contract.
     * @param salt The 32-byte random value used to create the contract address.
     */
    event ContractCreation(address indexed newContract, bytes32 indexed salt, bytes data);

    /**
     * @dev Emitted when a contract is created using the CREATE2 opcode with a cross-chain redeploy protection.
     * @param newContract The address of the newly created contract.
     * @param salt The 32-byte random value used to create the contract address.
     */
    event CrossChainDeployProtection(address indexed newContract, bytes32 indexed salt);

    /**
     * @dev Creates a new contract using the CREATE2 opcode.
     * @param salt The 32-byte random value used to create the contract address.
     * @param initCode The creation bytecode of the contract to deploy.
     * @return newContract The address of the newly created contract.
     */
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address newContract);

    /**
     * @dev Creates a new contract using the CREATE2 opcode with a cross-chain redeploy protection.
     * @param salt The 32-byte random value used to create the contract address.
     * @param initCode The creation bytecode of the contract to deploy.
     * @return newContract The address of the newly created contract.
     */
    function deployCreate2AndInit(bytes32 salt, bytes memory initCode, bytes memory data)
        external
        payable
        returns (address newContract);

    /**
     * @dev Creates a new contract using the CREATE3 opcode.
     * @param salt The 32-byte random value used to create the contract address.
     * @param initCode The creation bytecode of the contract to deploy.
     * @return newContract The address of the newly created contract.
     */
    function deployCreate3(bytes32 salt, bytes memory initCode) external payable returns (address newContract);

    /**
     * @dev Computes the address of a contract to be created via CREATE2.
     * @param salt The 32-byte random value used to create the contract address.
     * @param initCodeHash The keccak256 hash of the creation bytecode.
     * @return computedAddress The 20-byte address where the contract will be deployed.
     */
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash) external view returns (address computedAddress);

    /**
     * @dev Computes the address of a contract to be created via CREATE2 with cross-chain protection.
     * @param salt The 32-byte random value used to create the contract address.
     * @param initCodeHash The keccak256 hash of the creation bytecode.
     * @return computedAddress The 20-byte address where the contract will be deployed.
     */
    function computeCreate2Address(bytes32 salt, bytes32 initCodeHash, address deployer)
        external
        pure
        returns (address computedAddress);

    /**
     * @dev Computes the address of a contract to be created via CREATE3.
     * @param salt The 32-byte random value used to create the contract address.
     * @return computedAddress The 20-byte address where the contract will be deployed.
     */
    function computeCreate3Address(bytes32 salt) external view returns (address computedAddress);

    /**
     * @dev Computes the address of a contract to be created via CREATE3.
     * @param salt The 32-byte random value used to create the contract address.
     * @param deployer The 20-byte deployer address.
     * @return computedAddress The 20-byte address where the contract will be deployed.
     */
    function computeCreate3Address(bytes32 salt, address deployer) external pure returns (address computedAddress);
}
