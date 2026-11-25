// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {IRouter} from "../../src/interfaces/IRouter.sol";
import {Request} from "../../src/types.sol";

/// @title MockRouter
/// @notice Router that accepts every transfer and does nothing, for tests that need a router set
contract MockRouter is IRouter {
    function processTransfer(Request calldata, bytes calldata) external payable {}
}
