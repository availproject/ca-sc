// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockERC20
/// @notice Simple ERC20 mock for testing purposes
/// @dev Allows minting to any address for testing
contract MockERC20 is ERC20 {
    /// @notice Creates a new mock token
    /// @param name Token name
    /// @param symbol Token symbol
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    /// @notice Mints tokens to a specified address
    /// @param to Address to mint tokens to
    /// @param amount Amount of tokens to mint
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
