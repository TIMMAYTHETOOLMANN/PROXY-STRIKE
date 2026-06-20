"""
On-chain Contract Scanner
Deploys TacticalProxyScanner and batch-scans targets via Ethereum MCP.
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
        """Deploy TacticalProxyScanner to the target network"""
        with open("contracts/TacticalProxyScanner.sol", "r") as f:
            source = f.read()
        result = self.eth.deploy_contract_ui(
            source_code=source,
            network=network
        )
        self.scanner_address = result["address"]
        self.store.write_file(
            f"redteam/scanner_deployments/{network}.json",
            json.dumps({"address": self.scanner_address, "network": network, "timestamp": datetime.utcnow().isoformat()})
        )
        print(f"[SCANNER] Deployed on {network}: {self.scanner_address}")
        return self.scanner_address

    def scan_batch(self, targets: List[Dict], network: str = "ethereum_mainnet") -> List[Dict]:
        """Batch-scan addresses and return enriched results"""
        if not self.scanner_address:
            raise RuntimeError("Scanner not deployed. Call deploy_scanner() first.")

        addresses = [t["address"] for t in targets if t.get("chain", "").startswith("ethereum")]
        if not addresses:
            print("[SCANNER] No compatible targets for this network")
            return []

        # Encode scanBatch call
        from web3 import Web3
        w3 = Web3()
        abi = [
            {
                "inputs": [{"internalType": "address[]", "name": "targets", "type": "address[]"}],
                "name": "scanBatch",
                "outputs": [{"components": [
                    {"internalType": "address", "name": "target", "type": "address"},
                    {"internalType": "bool", "name": "isProxy", "type": "bool"},
                    {"internalType": "address", "name": "implAddress", "type": "address"},
                    {"internalType": "bool", "name": "hasBeforeTokenTransferHook", "type": "bool"},
                    {"internalType": "bool", "name": "hasAfterTokenTransferHook", "type": "bool"},
                    {"internalType": "bool", "name": "hasTaxPercentVariable", "type": "bool"},
                    {"internalType": "bool", "name": "hasSetFeeFunction", "type": "bool"},
                    {"internalType": "bool", "name": "hasMintFunction", "type": "bool"},
                    {"internalType": "uint8", "name": "riskScore", "type": "uint8"}
                ], "internalType": "struct TacticalProxyScanner.ScanResult[]", "name": "", "type": "tuple[]"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        contract = w3.eth.contract(address=self.scanner_address, abi=abi)
        data = contract.functions.scanBatch(addresses).build_transaction({"chainId": 1, "gas": 5000000})["data"]

        # Call via MCP (read-only staticcall)
        result = self.eth.call_contract(to=self.scanner_address, data=data)

        # Decode
        scanned = []
        for i, target in enumerate([t for t in targets if t.get("chain", "").startswith("ethereum")]):
            base = 2 + i * 576  # 9 fields × 64 hex chars
            raw = result[base:base + 576]
            risk_score = int(raw[-64:], 16) if raw[-64:] else 0
            scanned.append({
                "address": target["address"],
                "chain": target["chain"],
                "source": target.get("source", "unknown"),
                "isProxy": raw[0:64] != "0" * 64,
                "implAddress": "0x" + raw[64:128][-40:],
                "riskScore": risk_score,
                "timestamp": datetime.utcnow().isoformat()
            })

        # Persist
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.store.write_file(
            f"redteam/scans/scan_{network}_{timestamp}.json",
            json.dumps({"results": scanned, "count": len(scanned), "timestamp": datetime.utcnow().isoformat()})
        )

        high_risk = [s for s in scanned if s.get("riskScore", 0) >= 50]
        if high_risk:
            self.store.write_file(
                f"redteam/intel/verified_vulnerable.json",
                json.dumps(high_risk, indent=2)
            )
            print(f"[SCANNER] {len(high_risk)} high-risk targets saved to verified_vulnerable.json")

        return scanned

    def load_targets_from_bucket(self) -> List[Dict]:
        """Load Phase 1 target list from bucket"""
        files = self.store.list_files(directory="redteam/intel")
        target_files = [f for f in files if f.startswith("target_list_")]
        if not target_files:
            raise FileNotFoundError("No target list found in bucket. Run Phase 1 first.")
        latest = sorted(target_files)[-1]
        data = self.store.read_file(f"redteam/intel/{latest}")
        return json.loads(data)["targets"]
