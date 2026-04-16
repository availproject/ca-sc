// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title MockFeeOnTransfer
/// @notice ERC20 token with configurable fee on transfer for testing
/// @dev Demonstrates fee-on-transfer token behavior for Vault integration tests
/// @dev Fee is deducted from the transfer amount before transfer completes
contract MockFeeOnTransfer is ERC20, Ownable {
    /// @notice Fee percentage in basis points (100 = 1%, 9900 = 99%)
    uint256 public feePercent;

    /// @notice Maximum allowed fee: 99% (9900 basis points)
    uint256 public constant MAX_FEE = 9900;

    /// @notice Basis points divisor (10000 = 100%)
    uint256 public constant BPS = 10000;

    /// @notice Creates a new fee-on-transfer mock token
    /// @param name Token name
    /// @param symbol Token symbol
    constructor(string memory name, string memory symbol) ERC20(name, symbol) Ownable(msg.sender) {
        feePercent = 0;
    }

    /// @notice Sets the fee percentage
    /// @param _feePercent Fee in basis points (0-9900)
    /// @dev Only callable by owner
    function setFeePercent(uint256 _feePercent) external onlyOwner {
        require(_feePercent <= MAX_FEE, "Fee too high");
        feePercent = _feePercent;
    }

    /// @notice Mints tokens to a specified address
    /// @param to Address to mint tokens to
    /// @param amount Amount of tokens to mint
    /// @dev Only callable by owner
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /// @notice Burns tokens from a specified address
    /// @param from Address to burn tokens from
    /// @param amount Amount of tokens to burn
    /// @dev Only callable by owner
    function burn(address from, uint256 amount) external onlyOwner {
        _burn(from, amount);
    }

    /// @notice Overridden transfer function to deduct fee
    /// @param recipient Address to transfer tokens to
    /// @param amount Amount of tokens to transfer (before fee)
    /// @return bool Always returns true
    /// @dev Fee is calculated as: (amount * feePercent) / BPS
    /// @dev If fee > 0 and recipient is not address(0), deducts fee from amount
    function transfer(address recipient, uint256 amount) public override returns (bool) {
        if (feePercent > 0 && recipient != address(0)) {
            uint256 fee = (amount * feePercent) / BPS;
            uint256 netAmount = amount - fee;

            // Transfer fee to owner (acts as fee recipient)
            super.transfer(owner(), fee);
            // Transfer net amount to recipient
            super.transfer(recipient, netAmount);
            return true;
        }
        return super.transfer(recipient, amount);
    }

    /// @notice Overridden transferFrom function to deduct fee
    /// @param sender Address to transfer tokens from
    /// @param recipient Address to transfer tokens to
    /// @param amount Amount of tokens to transfer (before fee)
    /// @return bool Always returns true
    /// @dev Fee is calculated as: (amount * feePercent) / BPS
    /// @dev If fee > 0 and recipient is not address(0), deducts fee from amount
    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {
        if (feePercent > 0 && recipient != address(0)) {
            uint256 fee = (amount * feePercent) / BPS;
            uint256 netAmount = amount - fee;

            // Transfer fee to owner (acts as fee recipient)
            super.transferFrom(sender, owner(), fee);
            // Transfer net amount to recipient
            super.transferFrom(sender, recipient, netAmount);
            return true;
        }
        return super.transferFrom(sender, recipient, amount);
    }
}
