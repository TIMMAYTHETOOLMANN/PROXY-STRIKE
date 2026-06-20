// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @title Malicious Taxable ERC20 – For Controlled Red Team Training Only
/// @notice This contract is used ONLY in isolated test environments 
///         to demonstrate the OMENX attack vector.
contract TaxableERC20 is ERC20, Ownable {
    address public feeReceiver;
    uint256 public taxPercent = 10; // 10% default
    bool public taxEnabled = true;

    mapping(address => bool) public whitelist;

    constructor(
        string memory name,
        string memory symbol,
        address _feeReceiver
    ) ERC20(name, symbol) Ownable(msg.sender) {
        feeReceiver = _feeReceiver;
        _mint(msg.sender, 1000000 * 10**decimals());
    }

    function setTaxPercent(uint256 _percent) external onlyOwner {
        require(_percent <= 100, "Tax cannot exceed 100%");
        taxPercent = _percent;
    }

    function setFeeReceiver(address _receiver) external onlyOwner {
        feeReceiver = _receiver;
    }

    function toggleTax() external onlyOwner {
        taxEnabled = !taxEnabled;
    }

    function addToWhitelist(address account) external onlyOwner {
        whitelist[account] = true;
    }

    function _update(
        address from,
        address to,
        uint256 value
    ) internal override {
        if (taxEnabled && !whitelist[from] && !whitelist[to] && from != address(0)) {
            uint256 fee = (value * taxPercent) / 100;
            if (fee > 0) {
                super._update(from, feeReceiver, fee);
                value -= fee;
            }
        }
        super._update(from, to, value);
    }
}
