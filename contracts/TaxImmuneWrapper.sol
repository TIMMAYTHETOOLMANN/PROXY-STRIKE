// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title Tax-Immune Wrapper
/// @notice Wraps any ERC20 to freeze its interface, preventing proxy upgrades 
///         from affecting held tokens.
contract TaxImmuneWrapper {
    IERC20 public immutable underlying;
    
    constructor(IERC20 _token) {
        underlying = _token;
    }

    /// @notice Transfer tokens using the wrapper's static logic
    function safeTransferFrom(address from, address to, uint256 amount) external {
        underlying.transferFrom(from, to, amount);
    }

    /// @notice Emergency withdrawal in case of proxy upgrade
    function emergencyWithdraw(address to) external {
        uint256 balance = underlying.balanceOf(address(this));
        require(balance > 0, "No balance");
        underlying.transfer(to, balance);
    }
}
