"""
On-chain Contract Scanner
Deploys and interacts with TacticalProxyScanner to verify vulnerabilities.
"""
import json
from typing import List, Dict
from datetime import datetime

class ContractScanner:
    def __init__(self, ethereum_mcp, bucket_store):
        self.eth = ethereum_mcp
        self.store = bucket_store
        self.scanner_address = None

    def deploy_scanner(self, network: str = "ethereum_mainnet") -> str:
        """Deploy the TacticalProxyScanner contract"""
        with open("contracts/TacticalProxyScanner.sol", "r") as f:
            source = f.read()
        
        result = self.eth.deploy_contract_ui(
            source_code=source,
            network=network
        )
        self.scanner_address = result["address"]
        print(f"Scanner deployed at: {self.scanner_address}")
        return self.scanner_address

    def scan_batch(self, targets: List[Dict], network: str = "ethereum_mainnet") -> List[Dict]:
        """Batch scan a list of contract addresses"""
        if not self.scanner_address:
            self.deploy_scanner(network)

        # Filter targets by chain compatibility
        chain_targets = [t for t in targets if self._is_chain_supported(t["chain"], network)]
        
        if not chain_targets:
            return []

        addresses = [t["address"] for t in chain_targets]
        
        # Encode the scanBatch call
        from web3 import Web3
        w3 = Web3()
        # ABI for scanBatch
        abi = [{"inputs":[{"internalType":"address[]","name":"targets","type":"address[]"}],"name":"scanBatch","outputs":[{"components":[{"internalType":"address","name":"target","type":"address"},{"internalType":"bool","name":"isProxy","type":"bool"},{"internalType":"address","name":"implAddress","type":"address"},{"internalType":"bool","name":"hasBeforeTokenTransferHook","type":"bool"},{"internalType":"bool","name":"hasAfterTokenTransferHook","type":"bool"},{"internalType":"bool","name":"hasTaxPercentVariable","type":"bool"},{"internalType":"bool","name":"hasSetFeeFunction","type":"bool"},{"internalType":"bool","name":"hasMintFunction","type":"bool"},{"internalType":"uint8","name":"riskScore","type":"uint8"}],"internalType":"struct TacticalProxyScanner.ScanResult[]","name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"}]
        contract = w3.eth.contract(address=self.scanner_address, abi=abi)
        data = contract.functions.scanBatch(addresses).build_transaction()["data"]

        # Call via Ethereum MCP (read-only, no transaction)
        result = self.eth.call_contract(
            to=self.scanner_address,
            data=data
        )

        # Decode results
        scanned = self._decode_scan_results(result, chain_targets)
        
        # Persist
        self.store.write_file(
            f"redteam/scans/scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            json.dumps({"results": scanned, "timestamp": datetime.utcnow().isoformat()})
        )
        
        return scanned

    def _decode_scan_results(self, raw_data: str, targets: List[Dict]) -> List[Dict]:
        """Decode the raw scanBatch output"""
        from web3 import Web3
        w3 = Web3()
        
        # Parse the hex output
        # Each result: address (32 bytes), bool (32 bytes), address (32 bytes), 4 bools (32 bytes each), uint8 (32 bytes)
        # Total: 9 * 32 = 288 bytes per result
        results = []
        for i, target in enumerate(targets):
            offset = 2 + i * 288 * 2  # Skip '0x' and account for hex encoding
            data = raw_data[offset:offset + 288*2]
            
            # Extremely simplified decode – production would use proper ABI decoding
            results.append({
                "address": target["address"],
                "chain": target["chain"],
                "isProxy": True,
                "implAddress": "0x" + data[64:128],
                "riskScore": int(data[-64:], 16),
                "source": target.get("source", "unknown"),
                "timestamp": datetime.utcnow().isoformat()
            })
        
        return results

    def _is_chain_supported(self, chain: str, network: str) -> bool:
        """Check if the target chain matches the current network"""
        chain_map = {
            "ethereum_mainnet": ["ethereum_mainnet", "ethereum", "eth"],
            "bsc_mainnet": ["bsc_mainnet", "bsc", "bnb"],
            "sepolia": ["sepolia"],
            "local_testnet": ["local_testnet", "local"],
        }
        return any(chain.lower() in aliases for aliases in chain_map.get(network, []) for aliases in [aliases])
