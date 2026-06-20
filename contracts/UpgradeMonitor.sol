// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UpgradeMonitor {
    struct MonitoredProxy {
        address proxy;
        address currentImpl;
        uint256 lastBlock;
    }

    mapping(address => MonitoredProxy) public proxies;
    address[] public proxyList;

    event ImplChanged(address indexed proxy, address oldImpl, address newImpl, uint256 timestamp);

    function addProxy(address proxy, address impl) external {
        require(proxies[proxy].proxy == address(0), "already monitored");
        proxies[proxy] = MonitoredProxy(proxy, impl, block.number);
        proxyList.push(proxy);
    }

    function checkAndUpdate(address proxy) external returns (bool changed) {
        MonitoredProxy storage mp = proxies[proxy];
        require(mp.proxy != address(0), "not monitored");
        // simplistic staticcall to get implementation()
        (bool ok, bytes memory data) = proxy.staticcall(
            abi.encodeWithSignature("implementation()")
        );
        address currentImpl = ok && data.length >= 32 ? abi.decode(data, (address)) : address(0);
        if (currentImpl != mp.currentImpl) {
            emit ImplChanged(proxy, mp.currentImpl, currentImpl, block.timestamp);
            mp.currentImpl = currentImpl;
            mp.lastBlock = block.number;
            changed = true;
        }
    }

    function checkAll() external returns (uint256 count) {
        for (uint256 i = 0; i < proxyList.length; i++) {
            if (this.checkAndUpdate(proxyList[i])) count++;
        }
    }
}
