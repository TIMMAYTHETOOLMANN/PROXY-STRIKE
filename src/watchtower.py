"""
24/7 Watchtower Daemon
Monitors known vulnerable contracts for proxy upgrades and tax activation.
"""
import asyncio
import json
from datetime import datetime
from typing import List, Dict

class Watchtower:
    def __init__(self, hyperbrowser, ethereum_mcp, bucket_store, config):
        self.hb = hyperbrowser
        self.eth = ethereum_mcp
        self.store = bucket_store
        self.config = config
        self.monitored_contracts = []
        self.alert_history = []

    async def start(self):
        """Start the watchtower daemon"""
        print("[WATCHTOWER] Starting continuous monitoring...")
        await self._load_monitored_contracts()
        
        while True:
            try:
                await self._check_all_contracts()
                await self._scrape_new_threats()
                await asyncio.sleep(self.config.get("watch_interval", 3600))  # Default 1 hour
            except Exception as e:
                print(f"[WATCHTOWER] Error in monitoring loop: {e}")
                await asyncio.sleep(60)  # Retry after 1 minute

    async def _load_monitored_contracts(self):
        """Load the list of contracts to monitor from bucket"""
        try:
            data = await self.store.read_file("redteam/intel/verified_vulnerable.json")
            self.monitored_contracts = json.loads(data)
            print(f"[WATCHTOWER] Loaded {len(self.monitored_contracts)} contracts to monitor")
        except:
            print("[WATCHTOWER] No existing monitored contracts found")

    async def _check_all_contracts(self):
        """Check all monitored contracts for changes"""
        alerts = []
        for contract in self.monitored_contracts:
            changed = await self._check_implementation_change(contract)
            if changed:
                alerts.append({
                    "type": "IMPLEMENTATION_CHANGE",
                    "contract": contract["address"],
                    "chain": contract["chain"],
                    "old_impl": contract.get("last_impl"),
                    "new_impl": changed,
                    "timestamp": datetime.utcnow().isoformat()
                })
                contract["last_impl"] = changed
        
        if alerts:
            await self._send_alerts(alerts)
            await self._update_monitored_list()

    async def _check_implementation_change(self, contract: Dict) -> str:
        """Check if a proxy's implementation has changed"""
        try:
            # Call implementation() on the contract
            result = await self.eth.call_contract(
                to=contract["address"],
                data="0x5c60da1b"  # implementation() selector
            )
            current_impl = "0x" + result[-40:]
            
            if "last_impl" not in contract:
                contract["last_impl"] = current_impl
                return None
            
            if current_impl.lower() != contract["last_impl"].lower():
                return current_impl
            return None
        except Exception as e:
            print(f"[WATCHTOWER] Failed to check {contract['address']}: {e}")
            return None

    async def _scrape_new_threats(self):
        """Periodically scrape for new threats"""
        try:
            from intel_gatherer import IntelGatherer
            gatherer = IntelGatherer(self.hb, None, self.store)
            new_targets = await gatherer._scrape_token_sniffer()
            
            # Add new targets to monitored list
            for target in new_targets:
                if not any(c["address"] == target["address"] for c in self.monitored_contracts):
                    self.monitored_contracts.append(target)
            
            print(f"[WATCHTOWER] Added {len(new_targets)} new potential targets")
        except Exception as e:
            print(f"[WATCHTOWER] Failed to scrape new threats: {e}")

    async def _send_alerts(self, alerts: List[Dict]):
        """Send alerts to the bucket store"""
        for alert in alerts:
            alert_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
            await self.store.write_file(
                f"redteam/alerts/{alert_id}.json",
                json.dumps(alert, indent=2)
            )
            self.alert_history.append(alert)
            print(f"[WATCHTOWER] 🚨 ALERT: {alert['contract']} implementation changed!")

    async def _update_monitored_list(self):
        """Update the monitored contracts list in the bucket"""
        await self.store.write_file(
            "redteam/intel/verified_vulnerable.json",
            json.dumps(self.monitored_contracts, indent=2)
        )
