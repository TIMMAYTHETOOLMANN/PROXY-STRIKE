// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Tactical Proxy Vulnerability Scanner – Red Team Recon
/// @notice Detects EIP-1967, UUPS, Transparent, and Beacon proxies
///         plus tax hooks, mint functions, and fee setters.
contract TacticalProxyScanner {
    struct ScanResult {
        address target;
        bool isProxy;
        ProxyType proxyType;          // 0=NONE, 1=EIP1967, 2=UUPS, 3=TRANSPARENT, 4=BEACON
        address implAddress;
        bool hasBeforeTokenTransferHook;
        bool hasAfterTokenTransferHook;
        bool hasTaxPercentVariable;
        bool hasSetFeeFunction;
        bool hasMintFunction;
        uint8 riskScore;
    }

    enum ProxyType { NONE, EIP1967, UUPS, TRANSPARENT, BEACON }

    // EIP-1967 storage slots
    bytes32 private constant IMPLEMENTATION_SLOT  = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 private constant ADMIN_SLOT           = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 private constant BEACON_SLOT          = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    // UUPS function selectors
    bytes4 private constant UUPS_UPGRADE_TO          = 0x3659cfe6;
    bytes4 private constant UUPS_UPGRADE_TO_AND_CALL = 0x4f1ef286;

    // Transparent proxy admin selectors
    bytes4 private constant ADMIN_FALLBACK = 0xf851a440; // admin()

    // Tax / exploit selectors
    bytes4 private constant BEFORE_TOKEN_TRANSFER = 0x9d0f3c6a;
    bytes4 private constant AFTER_TOKEN_TRANSFER  = 0x2d93e1e9;
    bytes4 private constant SET_TAX_PERCENT       = 0x4a4a7d41;
    bytes4 private constant SET_FEE               = 0x69fe0e2d;
    bytes4 private constant MINT                  = 0x40c10f19;
    bytes4 private constant INITIALIZE            = 0xc4d66de8; // initialize()

    function scan(address target) public view returns (ScanResult memory result) {
        result.target = target;
        (result.proxyType, result.implAddress) = _detectProxy(target);
        if (result.proxyType != ProxyType.NONE) {
            result.isProxy = true;
            result.riskScore += 25; // proxy is itself a risk vector
        } else {
            result.implAddress = target;
        }

        address impl = result.implAddress;
        if (impl == address(0)) impl = target;

        if (_hasFunction(impl, BEFORE_TOKEN_TRANSFER)) {
            result.hasBeforeTokenTransferHook = true; result.riskScore += 15;
        }
        if (_hasFunction(impl, AFTER_TOKEN_TRANSFER)) {
            result.hasAfterTokenTransferHook = true; result.riskScore += 15;
        }
        if (_hasFunction(impl, SET_TAX_PERCENT) || _hasFunction(impl, SET_FEE)) {
            result.hasSetFeeFunction = true; result.riskScore += 25;
        }
        if (_hasFunction(impl, MINT)) {
            result.hasMintFunction = true; result.riskScore += 25;
        }
        // Initializable pattern = potential upgrade vulnerability
        if (_hasFunction(impl, INITIALIZE)) {
            result.riskScore += 10;
        }
        result.hasTaxPercentVariable = _checkStorageSlot(impl, 5);
        if (result.hasTaxPercentVariable) result.riskScore += 10;
        if (result.riskScore > 100) result.riskScore = 100;
    }

    function scanBatch(address[] calldata targets) external view returns (ScanResult[] memory) {
        ScanResult[] memory results = new ScanResult[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            results[i] = scan(targets[i]);
        }
        return results;
    }

    // ── Proxy Detection ──────────────────────────────────────────

    function _detectProxy(address target) private view returns (ProxyType pType, address impl) {
        // 1. EIP-1967 implementation slot
        bytes32 implSlot = _readSlot(target, IMPLEMENTATION_SLOT);
        if (implSlot != bytes32(0)) {
            return (ProxyType.EIP1967, address(uint160(uint256(implSlot))));
        }

        // 2. Transparent proxy: admin slot exists
        bytes32 adminSlot = _readSlot(target, ADMIN_SLOT);
        if (adminSlot != bytes32(0)) {
            // Also check for implementation() function
            (bool ok, bytes memory data) = target.staticcall(
                abi.encodeWithSignature("implementation()")
            );
            if (ok && data.length >= 32) {
                return (ProxyType.TRANSPARENT, abi.decode(data, (address)));
            }
        }

        // 3. UUPS: has upgradeTo / upgradeToAndCall in the implementation
        // We'll check the target itself for these selectors (UUPS stores logic in the proxy)
        if (_hasFunction(target, UUPS_UPGRADE_TO) || _hasFunction(target, UUPS_UPGRADE_TO_AND_CALL)) {
            return (ProxyType.UUPS, target); // UUPS: proxy IS the implementation
        }

        // 4. Beacon proxy
        bytes32 beaconSlot = _readSlot(target, BEACON_SLOT);
        if (beaconSlot != bytes32(0)) {
            return (ProxyType.BEACON, address(uint160(uint256(beaconSlot))));
        }

        // 5. Fallback: try implementation() call
        (bool ok2, bytes memory data2) = target.staticcall(
            abi.encodeWithSignature("implementation()")
        );
        if (ok2 && data2.length >= 32) {
            address implAddr = abi.decode(data2, (address));
            if (implAddr != address(0) && implAddr != target) {
                return (ProxyType.EIP1967, implAddr);
            }
        }

        return (ProxyType.NONE, address(0));
    }

    // ── Helpers ───────────────────────────────────────────────────

    function _readSlot(address contractAddr, bytes32 slot) private view returns (bytes32 value) {
        assembly { value := sload(slot) }
    }

    function _hasFunction(address contractAddr, bytes4 selector) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(contractAddr) }
        if (size == 0) return false;
        bytes memory code = new bytes(64);
        assembly { extcodecopy(contractAddr, add(code, 32), 0, 64) }
        bytes4 push4Selector = bytes4(0x63) | (selector >> 24);
        for (uint256 i = 0; i < 32; i++) {
            bytes4 chunk;
            assembly { chunk := mload(add(add(code, 32), i)) }
            if (chunk == push4Selector) return true;
        }
        return false;
    }

    function _checkStorageSlot(address contractAddr, uint256 slot) private view returns (bool) {
        bytes32 value;
        assembly { value := sload(slot) }
        return value != 0 && uint256(value) < 10000;
    }
}
