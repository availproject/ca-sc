// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import {Action} from "../types.sol";

interface ICaRouter {
    function processTransfer(Action calldata request, bytes calldata data) external payable;
}
