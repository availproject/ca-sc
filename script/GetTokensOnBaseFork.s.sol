// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Script, console} from "forge-std/Script.sol";

contract GetTokensOnBaseFork is Script {
    address constant USDC_BASE = 0x833589fCD6eDb6E08f4c7C32D4f71b54bA02913A;
    address constant USDbC_BASE = 0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA;
    address constant WETH_BASE = 0x4200000000000000000000000000000000000006;
    address constant CBETH_BASE = 0x2Ae3F1Ec7F1F5012CF6abFB7B03a88C2d355726C;

    uint256 constant FORK_BLOCK_NUMBER = 20_000_000;

    struct TokenInfo {
        string name;
        address addr;
        address whale;
        uint256 amount;
    }

    // Known whale addresses on Base
    address constant USDC_WHALE = 0x8EB8a3b98659Cce540Db5B4A8f76a3aC4b66dFb1;
    address constant USDbC_WHALE = 0x4C456F03A4382C3d3a9Af4c3e8E0f5F4B3f2d5E7;
    address constant WETH_WHALE = 0xF977814e90dA44bFA03b6295A0616a897441aceC;

    function run() external {
        // Fork Base network
        uint256 forkId = vm.createFork(
            vm.rpcUrl("base"),
            FORK_BLOCK_NUMBER
        );
        vm.selectFork(forkId);

        console.log("Forked Base at block:", FORK_BLOCK_NUMBER);
        console.log("Current chain ID:", block.chainid);

        // Define the address to give tokens to
        address recipient = vm.envOr("RECIPIENT_ADDRESS", msg.sender);
        console.log("\nRecipient:", recipient);

        // Give native ETH
        uint256 ethAmount = 100 ether;
        vm.deal(recipient, ethAmount);
        console.log("\n=== Native ETH ===");
        console.log("Sent:", ethAmount / 1e18, "ETH");
        console.log("Balance:", recipient.balance / 1e18, "ETH");

        // Transfer tokens from whales
        TokenInfo[] memory tokens = new TokenInfo[](3);
        tokens[0] = TokenInfo({
            name: "USDC",
            addr: USDC_BASE,
            whale: USDC_WHALE,
            amount: 1_000_000 * 1e6 // 1M USDC (6 decimals)
        });
        tokens[1] = TokenInfo({
            name: "USDbC",
            addr: USDbC_BASE,
            whale: USDbC_WHALE,
            amount: 1_000_000 * 1e18 // 1M USDbC (18 decimals)
        });
        tokens[2] = TokenInfo({
            name: "WETH",
            addr: WETH_BASE,
            whale: WETH_WHALE,
            amount: 100 * 1e18 // 100 WETH
        });

        console.log("\n=== ERC20 Tokens ===");
        for (uint256 i = 0; i < tokens.length; i++) {
            _transferTokens(tokens[i], recipient);
        }

        console.log("\n=== Final Balances ===");
        console.log("ETH:", recipient.balance / 1e18);
        _logTokenBalance("USDC", USDC_BASE, recipient, 6);
        _logTokenBalance("USDbC", USDbC_BASE, recipient, 18);
        _logTokenBalance("WETH", WETH_BASE, recipient, 18);
        _logTokenBalance("cbETH", CBETH_BASE, recipient, 18);
    }

    function _transferTokens(
        TokenInfo memory token,
        address recipient
    ) internal {
        console.log("\n---", token.name, "---");

        // Prank as the whale address and transfer tokens
        vm.startPrank(token.whale);

        // Approve the transfer
        (bool success, ) = token.addr.call(
            abi.encodeWithSignature(
                "approve(address,uint256)",
                recipient,
                token.amount
            )
        );
        require(success, "Approval failed");

        // Transfer tokens
        (success, ) = token.addr.call(
            abi.encodeWithSignature(
                "transfer(address,uint256)",
                recipient,
                token.amount
            )
        );
        require(success, "Transfer failed");

        vm.stopPrank();

        console.log("Sent:", _formatAmount(token.amount, token.addr));
    }

    function _formatAmount(uint256 amount, address token) internal view returns (string memory) {
        // Try to get decimals
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("decimals()")
        );

        if (success && data.length > 0) {
            uint8 decimals = abi.decode(data, (uint8));
            uint256 divisor = 10 ** decimals;
            return string(abi.encodePacked(
                vm.toString(amount / divisor),
                ".",
                vm.toString((amount % divisor) / (divisor / 10))
            ));
        }

        return vm.toString(amount);
    }

    function _logTokenBalance(
        string memory name,
        address token,
        address account,
        uint8 decimals
    ) internal view {
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSignature("balanceOf(address)", account)
        );

        if (success && data.length > 0) {
            uint256 balance = abi.decode(data, (uint256));
            uint256 divisor = 10 ** decimals;
            console.log(name, ":", vm.toString(balance / divisor));
        }
    }

    // Alternative method: Get tokens from Uniswap pools
    function runUniswapSwap() external {
        uint256 forkId = vm.createFork(vm.rpcUrl("base"));
        vm.selectFork(forkId);

        address recipient = vm.envOr("RECIPIENT_ADDRESS", msg.sender);
        uint256 ethAmount = 100 ether;

        vm.deal(recipient, ethAmount);
        console.log("Gave recipient", ethAmount / 1e18, "ETH");

        // Uniswap V3 Router on Base
        address constant UNISWAP_V3_ROUTER = 0xE592427A0AEce92De3Edee1F18E0157C05861564;
        address WETH = WETH_BASE;
        address USDC = USDC_BASE;

        // ETH -> USDC swap path
        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = USDC;

        // Approve WETH and swap
        vm.startPrank(recipient);

        // Wrap ETH to WETH
        (bool success, ) = WETH.call{value: 10 ether}(
            abi.encodeWithSignature("deposit()")
        );
        require(success, "WETH deposit failed");

        // Approve Uniswap Router
        (success, ) = WETH.call(
            abi.encodeWithSignature(
                "approve(address,uint256)",
                UNISWAP_V3_ROUTER,
                10 ether
            )
        );
        require(success, "WETH approval failed");

        // Execute swap
        (success, ) = UNISWAP_V3_ROUTER.call{
            value: 10 ether
        }(
            abi.encodeWithSignature(
                "exactInputSingle((address address address uint256 uint256 uint256 uint160 bytes))",
                abi.encode(
                    WETH,      // tokenIn
                    USDC,      // tokenOut
                    500,       // fee (0.05%)
                    recipient, // recipient
                    block.timestamp + 300, // deadline
                    10 ether,  // amountIn
                    0,         // amountOutMinimum (accept any)
                    0,         // sqrtPriceLimitX96 (no limit)
                    ""         // data
                )
            )
        );
        require(success, "Swap failed");

        vm.stopPrank();

        console.log("Swapped 10 ETH for USDC via Uniswap");
    }
}
