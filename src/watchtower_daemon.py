"""
Watchtower Daemon – 24/7 continuous monitoring of fortified proxies.
Polls UpgradeMonitor.checkAll() every 60 seconds.
Alerts bucket on any unexpected implementation change.
"""
import asyncio
import json
import os
from datetime import datetime

class WatchtowerDaemon:
    def __init__(self, ethereum_mcp, bucket_store):
        self.eth = ethereum_mcp
        self.store = bucket_store
        self.monitor_address = self._load_monitor_address()
        self.interval_seconds = int(os.getenv("WATCHTOWER_INTERVAL", "60"))
        self.alert_threshold = int(os.getenv("WATCHTOWER_ALERT_THRESHOLD", "1"))

    def _load_monitor_address(self) -> str:
        """Load UpgradeMonitor address from fortifier deployment bucket."""
        data = self.store.read_file("redteam/fortifier/deployments.json")
        deployments = json.loads(data)["assets"]
        for asset in deployments:
            if "monitor_address" in asset:
                return asset["monitor_address"]
        raise RuntimeError("No monitor deployment found in bucket. Run Fortifier first.")

    async def poll(self) -> int:
        """Call checkAll() on the monitor; return number of changes detected."""
        try:
            # Encode checkAll()
            result = self.eth.call_contract(
                to=self.monitor_address,
                data="0x9b1aee39"  # checkAll() selector
            )
            # Decode uint256 count
            count = int(result, 16) if result else 0
            return count
        except Exception as e:
            print(f"[WATCHTOWER] Poll error: {e}")
            return 0

    async def alert(self, count: int):
        """Write alert to bucket and print to stderr."""
        alert = {
            "type": "IMPLEMENTATION_CHANGE",
            "monitor": self.monitor_address,
            "changes_detected": count,
            "timestamp": datetime.utcnow().isoformat(),
            "severity": "CRITICAL" if count >= self.alert_threshold else "WARNING"
        }
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.store.write_file(
            f"redteam/watchtower/alerts/{timestamp}.json",
            json.dumps(alert, indent=2)
        )
        print(f"[WATCHTOWER] 🚨 ALERT: {count} implementation changes detected!", flush=True)

    async def run_forever(self):
        """Main daemon loop."""
        print(f"[WATCHTOWER] Monitoring {self.monitor_address} every {self.interval_seconds}s", flush=True)
        while True:
            count = await self.poll()
            if count > 0:
                await self.alert(count)
            else:
                print(f"[WATCHTOWER] ✓ All clear — {datetime.utcnow().isoformat()}", flush=True)
            await asyncio.sleep(self.interval_seconds)

if __name__ == "__main__":
    # In production, these would be real MCP client instances injected via env/config
    async def main():
        daemon = WatchtowerDaemon(None, None)  # Replace with actual clients
        await daemon.run_forever()
    asyncio.run(main())
