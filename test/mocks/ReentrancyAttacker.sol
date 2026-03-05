// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Vault} from "../../contracts/Vault.sol";

contract ReentrancyAttacker {
    Vault public vault;
    uint256 public attackCount;
    uint256 public maxAttacks;
    
    constructor(address _vault) {
        vault = Vault(_vault);
    }
    
    function attackDeposit(
        Vault.Request calldata request,
        bytes calldata signature,
        uint256 chainIndex
    ) external payable {
        attackCount = 0;
        maxAttacks = 5;
        vault.deposit{value: msg.value}(request, signature, chainIndex);
    }
    
    function attackFulfil(
        Vault.Request calldata request,
        bytes calldata signature
    ) external payable {
        attackCount = 0;
        maxAttacks = 5;
        vault.fulfil{value: msg.value}(request, signature);
    }
    
    function attackSettle(
        Vault.SettleData calldata settleData,
        bytes calldata signature
    ) external {
        attackCount = 0;
        maxAttacks = 5;
        vault.settle(settleData, signature);
    }
    
    receive() external payable {
        attackCount++;
        if (attackCount < maxAttacks) {
            // Attempt reentrancy - will be blocked by ReentrancyGuardTransient
        }
    }
}
