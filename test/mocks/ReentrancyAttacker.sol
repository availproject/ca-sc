// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Vault} from "../../contracts/Vault.sol";

contract ReentrancyAttacker {
    Vault public vault;
    uint256 public attackCount;
    uint256 public maxAttacks;
    
    // Attack mode enum
    enum AttackMode { NONE, DEPOSIT, FULFIL, SETTLE }
    AttackMode public currentMode;
    
    // Store attack parameters for reentrancy attempts
    Vault.Request public pendingRequest;
    bytes public pendingSignature;
    uint256 public pendingChainIndex;
    Vault.SettleData public pendingSettleData;
    
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
        currentMode = AttackMode.DEPOSIT;
        
        // Store parameters for reentrancy attempt
        pendingRequest = request;
        pendingSignature = signature;
        pendingChainIndex = chainIndex;
        
        vault.deposit{value: msg.value}(request, signature, chainIndex);
    }
    
    function attackFulfil(
        Vault.Request calldata request,
        bytes calldata signature
    ) external payable {
        attackCount = 0;
        maxAttacks = 5;
        currentMode = AttackMode.FULFIL;
        
        // Store parameters for reentrancy attempt
        pendingRequest = request;
        pendingSignature = signature;
        
        vault.fulfil{value: msg.value}(request, signature);
    }
    
    function attackSettle(
        Vault.SettleData calldata settleData,
        bytes calldata signature
    ) external {
        attackCount = 0;
        maxAttacks = 5;
        currentMode = AttackMode.SETTLE;
        
        // Store parameters for reentrancy attempt
        pendingSettleData = settleData;
        pendingSignature = signature;
        
        vault.settle(settleData, signature);
    }
    
    receive() external payable {
        attackCount++;
        if (attackCount < maxAttacks) {
            // Attempt reentrancy based on current mode
            if (currentMode == AttackMode.DEPOSIT) {
                vault.deposit{value: msg.value}(pendingRequest, pendingSignature, pendingChainIndex);
            } else if (currentMode == AttackMode.FULFIL) {
                vault.fulfil{value: msg.value}(pendingRequest, pendingSignature);
            } else if (currentMode == AttackMode.SETTLE) {
                vault.settle(pendingSettleData, pendingSignature);
            }
        }
    }
}
