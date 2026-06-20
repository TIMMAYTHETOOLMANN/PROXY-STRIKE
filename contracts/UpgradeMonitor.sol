// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Upgrade Monitor
/// @notice Detects and logs when a proxy's implementation changes
contract UpgradeMonitor {
    event ImplementationChanged(
        address indexed proxy,
        address indexed oldImpl,
        address indexed newImpl,
        uint256 timestamp
    );

    mapping(address => address) public lastKnownImpl;

    function register(address proxy) external {
        address impl = _getImplementation(proxy);
        require(impl != address(0), "Not a proxy");
        lastKnownImpl[proxy] = impl;
    }

    function check(address proxy) external returns (bool changed) {
        address currentImpl = _getImplementation(proxy);
        address previousImpl = lastKnownImpl[proxy];

        if (currentImpl != previousImpl && previousImpl != address(0)) {
            emit ImplementationChanged(proxy, previousImpl, currentImpl, block.timestamp);
            lastKnownImpl[proxy] = currentImpl;
            return true;
        }
        return false;
    }

    function checkBatch(address[] calldata proxies) external returns (bool[] memory) {
        bool[] memory results = new bool[](proxies.length);
        for (uint256 i = 0; i < proxies.length; i++) {
            results[i] = check(proxies[i]);
        }
        return results;
    }

    function _getImplementation(address proxy) private view returns (address) {
        bytes32 IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
        bytes32 impl;
        assembly {
            impl := sload(IMPL_SLOT)
        }
        return address(uint160(uint256(impl)));
    }
}
