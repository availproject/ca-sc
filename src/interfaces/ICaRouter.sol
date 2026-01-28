// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { RouterAction } from "../types.sol";

interface ICaRouter {
    function processTransfer(RouterAction calldata request, bytes calldata data) external payable;
}
