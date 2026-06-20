// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TaxableERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;
    string public name = "TaxableToken";
    string public symbol = "TAX";
    uint8 public decimals = 18;
    address public owner;

    uint256 public taxPercent = 5;  // 5% tax
    address public taxCollector;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event TaxCollected(address indexed from, uint256 taxAmount);
    event TaxPercentUpdated(uint256 newPercent);

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    constructor(address _taxCollector) {
        owner = msg.sender;
        taxCollector = _taxCollector;
        totalSupply = 1_000_000 * 1e18;
        balanceOf[msg.sender] = totalSupply;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        _beforeTokenTransfer(msg.sender, to, amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        _beforeTokenTransfer(from, to, amount);
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function setTaxPercent(uint256 _newPercent) external onlyOwner {
        taxPercent = _newPercent;
        emit TaxPercentUpdated(_newPercent);
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal {
        if (from != address(0) && to != address(0)) {
            uint256 tax = (amount * taxPercent) / 100;
            if (tax > 0) {
                balanceOf[from] -= tax;
                balanceOf[taxCollector] += tax;
                emit TaxCollected(from, tax);
                emit Transfer(from, taxCollector, tax);
            }
        }
    }
}
