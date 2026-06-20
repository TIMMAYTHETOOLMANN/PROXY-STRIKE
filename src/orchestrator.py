"""
Red‑Team Recon Orchestrator – mainnet target acquisition.
Stops after verified_targets.json is written. No fortification, no watchtower.
"""
import asyncio
import json
from datetime import datetime
from src.intel_gatherer import IntelGatherer
from src.scanner import ContractScanner

class RedTeamOrchestrator:
    def __init__(self, hb_client, web_client, stealth_client, eth_mcp, bucket):
        self.intel = IntelGatherer(hb_client, web_client, stealth_client, bucket)
        self.scanner = ContractScanner(eth_mcp, bucket)

    async def run_recon(self, network: str = "ethereum_mainnet"):
        """Full recon pipeline: gather → scan → verify → export."""
        print(f"[RECON] Starting mainnet reconnaissance on {network}")

        # Phase 1: Intelligence gathering (stealth + Dune + BscScan)
        print("[RECON] Phase 1: Crawling sources...")
        targets = await self.intel.crawl()
        print(f"[RECON] Phase 1 complete: {len(targets)} raw targets")

        # Phase 2: Deploy scanner and batch‑scan
        print("[RECON] Phase 2: Deploying scanner...")
        scanner_addr = self.scanner.deploy_scanner(network=network)
        print(f"[RECON] Scanner deployed at {scanner_addr}")

        results = self.scanner.scan_batch(targets, network=network)
        print(f"[RECON] Phase 2 complete: {len(results)} scanned")

        # Phase 3: Filter and export
        verified = [r for r in results if r.get("riskScore", 0) >= 70]
        self.scanner.store.write_file(
            "redteam/intel/verified_targets.json",
            json.dumps({
                "targets": verified,
                "count": len(verified),
                "timestamp": datetime.utcnow().isoformat(),
                "network": network
            }, indent=2)
        )
        print(f"[RECON] Complete: {len(verified)} verified targets exported")
        return verified
