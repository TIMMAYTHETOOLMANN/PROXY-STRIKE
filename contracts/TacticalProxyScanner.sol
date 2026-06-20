// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Tactical Proxy Vulnerability Scanner
/// @notice On-chain contract that detects OMENX/SMC risk vectors
contract TacticalProxyScanner {
    struct ScanResult {
        address target;
        bool isProxy;
        address implAddress;
        bool hasBeforeTokenTransferHook;
        bool hasAfterTokenTransferHook;
        bool hasTaxPercentVariable;
        bool hasSetFeeFunction;
        bool hasMintFunction;
        uint8 riskScore;
    }

    bytes32 private constant IMPLEMENTATION_SLOT = 
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    bytes4 private constant BEFORE_TOKEN_TRANSFER = 0x9d0f3c6a;
    bytes4 private constant AFTER_TOKEN_TRANSFER  = 0x2d93e1e9;
    bytes4 private constant SET_TAX_PERCENT       = 0x4a4a7d41;
    bytes4 private constant SET_FEE               = 0x69fe0e2d;
    bytes4 private constant MINT                  = 0x40c10f19;

    function scan(address target) public view returns (ScanResult memory result) {
        result.target = target;
        address impl = _getImplementation(target);
        if (impl != address(0)) {
            result.isProxy = true;
            result.implAddress = impl;
            result.riskScore += 20;
        } else {
            impl = target;
        }
        if (impl != address(0) && _hasFunction(impl, BEFORE_TOKEN_TRANSFER)) {
            result.hasBeforeTokenTransferHook = true; result.riskScore += 15;
        }
        if (impl != address(0) && _hasFunction(impl, AFTER_TOKEN_TRANSFER)) {
            result.hasAfterTokenTransferHook = true; result.riskScore += 15;
        }
        if (impl != address(0) && (_hasFunction(impl, SET_TAX_PERCENT) || _hasFunction(impl, SET_FEE))) {
            result.hasSetFeeFunction = true; result.riskScore += 25;
        }
        if (impl != address(0) && _hasFunction(impl, MINT)) {
            result.hasMintFunction = true; result.riskScore += 25;
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

    function _getImplementation(address proxy) private view returns (address) {
        (bool success, bytes memory data) = proxy.staticcall(
            abi.encodeWithSignature("implementation()")
        );
        if (success && data.length >= 32) {
            return abi.decode(data, (address));
        }
        bytes32 impl;
        assembly { impl := sload(IMPLEMENTATION_SLOT) }
        if (impl != bytes32(0)) return address(uint160(uint256(impl)));
        return address(0);
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
