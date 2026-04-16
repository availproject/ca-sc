// SPDX-License-Identifier: MIT
pragma solidity ^0.8.29;

import { Request } from "../types.sol";

interface ICaRouter {
    function processTransfer(Request calldata request, bytes calldata data) external payable;
}
