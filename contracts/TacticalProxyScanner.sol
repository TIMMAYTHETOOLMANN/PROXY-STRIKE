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
        uint8 riskScore; // 0-100
    }

    // EIP-1967 implementation slot
    bytes32 private constant IMPLEMENTATION_SLOT = 
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // Function selectors
    bytes4 private constant BEFORE_TOKEN_TRANSFER = 0x9d0f3c6a;
    bytes4 private constant AFTER_TOKEN_TRANSFER  = 0x2d93e1e9;
    bytes4 private constant SET_TAX_PERCENT       = 0x4a4a7d41;
    bytes4 private constant SET_FEE               = 0x69fe0e2d;
    bytes4 private constant MINT                  = 0x40c10f19;

    function scan(address target) public view returns (ScanResult memory result) {
        result.target = target;
        result.isProxy = false;
        result.riskScore = 0;

        // Check if target is a proxy
        address impl = _getImplementation(target);
        if (impl != address(0)) {
            result.isProxy = true;
            result.implAddress = impl;
            result.riskScore += 20; // Base proxy risk
        } else {
            impl = target; // Scan the contract itself
        }

        // Check for hooks
        if (_hasFunction(impl, BEFORE_TOKEN_TRANSFER)) {
            result.hasBeforeTokenTransferHook = true;
            result.riskScore += 15;
        }
        if (_hasFunction(impl, AFTER_TOKEN_TRANSFER)) {
            result.hasAfterTokenTransferHook = true;
            result.riskScore += 15;
        }

        // Check for tax functions
        if (_hasFunction(impl, SET_TAX_PERCENT) || _hasFunction(impl, SET_FEE)) {
            result.hasSetFeeFunction = true;
            result.riskScore += 25;
        }

        // Check for mint
        if (_hasFunction(impl, MINT)) {
            result.hasMintFunction = true;
            result.riskScore += 25;
        }

        // Check storage slot for tax variable (heuristically check slot 5)
        result.hasTaxPercentVariable = _checkStorageSlot(impl, 5);
        if (result.hasTaxPercentVariable) {
            result.riskScore += 10;
        }

        // Cap risk score
        if (result.riskScore > 100) result.riskScore = 100;
    }

    function scanBatch(address[] calldata targets) 
        external 
        view 
        returns (ScanResult[] memory) 
    {
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

        // Fallback: EIP-1967 storage slot
        bytes32 impl;
        assembly {
            impl := sload(IMPLEMENTATION_SLOT)
        }
        if (impl != bytes32(0)) {
            return address(uint160(uint256(impl)));
        }

        return address(0);
    }

    function _hasFunction(address contractAddr, bytes4 selector) 
        private 
        view 
        returns (bool) 
    {
        (bool success, ) = contractAddr.staticcall(
            abi.encodeWithSelector(selector, address(0), address(0), 0)
        );
        // Even if it reverts, it might still exist — we check if a call was possible
        return success || _checkBytecode(contractAddr, selector);
    }

    function _checkBytecode(address contractAddr, bytes4 selector) 
        private 
        view 
        returns (bool) 
    {
        uint256 size;
        assembly {
            size := extcodesize(contractAddr)
        }
        if (size == 0) return false;

        // Read first 64 bytes of bytecode and check for selector
        bytes memory code = new bytes(64);
        assembly {
            extcodecopy(contractAddr, add(code, 32), 0, 64)
        }
        
        // Simple pattern match for PUSH4 selector
        bytes4 push4Selector = bytes4(0x63) | (selector >> 24);
        for (uint256 i = 0; i < 32; i++) {
            bytes4 chunk;
            assembly {
                chunk := mload(add(add(code, 32), i))
            }
            if (chunk == push4Selector) return true;
        }
        return false;
    }

    function _checkStorageSlot(address contractAddr, uint256 slot) 
        private 
        view 
        returns (bool) 
    {
        bytes32 value;
        assembly {
            mstore(0, slot)
            let ptr := mload(0x40)
            mstore(ptr, 0x8da5cb5b00000000000000000000000000000000000000000000000000000000)
            if iszero(staticcall(gas(), contractAddr, ptr, 4, 0, 0)) {
                value := 0
            }
            // Actually read the storage slot directly
            value := sload(slot)
        }
        // If slot contains a small non-zero value, it could be a tax parameter
        return value != 0 && uint256(value) < 10000;
    }
}
