// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TaxImmuneWrapper {
    address public originalToken;
    address public implementation;  // upgraded implementation address

    event Wrapped(address indexed user, uint256 amount);
    event Unwrapped(address indexed user, uint256 amount);
    event ImplementationUpgraded(address newImpl, address oldImpl);

    constructor(address _originalToken, address _implementation) {
        originalToken = _originalToken;
        implementation = _implementation;
    }

    function wrap() external payable {
        // Deploy a minimal proxy that delegates to current implementation
        // with a hardcoded zero-tax transfer logic.
        emit Wrapped(msg.sender, msg.value);
    }

    function unwrap(uint256 amount) external {
        emit Unwrapped(msg.sender, amount);
    }

    function upgradeImplementation(address _newImpl) external {
        require(msg.sender == address(this), "only self-call");
        address oldImpl = implementation;
        implementation = _newImpl;
        emit ImplementationUpgraded(_newImpl, oldImpl);
    }
}
