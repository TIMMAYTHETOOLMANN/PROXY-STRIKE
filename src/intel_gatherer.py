"""
Intel Gatherer – OSINT + live pull module
Performs mainnet reconnaissance to build target lists.
All operations are READ-ONLY.
"""
import asyncio
import json
from typing import List, Dict
from datetime import datetime

class IntelGatherer:
    def __init__(self, hb_client, web_client, stealth_client, bucket_store):
        self.hb = hb_client
        self.web = web_client
        self.stealth = stealth_client   # mcp-stealth-chrome
        self.store = bucket_store
        self.targets = []

    async def crawl(self) -> List[Dict]:
        """Execute full intelligence gathering pipeline"""
        tasks = [
            self._scrape_token_sniffer_stealth(),
            self._scrape_bscscan_unverified(),
            self._scrape_etherscan_proxies(),
            self._scrape_dune(),
            self._web_search_threat_intel(),
        ]
        results = await asyncio.gather(*tasks)
        
        # Flatten and deduplicate
        all_targets = []
        for result in results:
            all_targets.extend(result)
        
        self.targets = self._deduplicate(all_targets)
        await self._persist(self.targets)
        return self.targets

    async def _scrape_token_sniffer_stealth(self) -> List[Dict]:
        """
        Scrape Token Sniffer trending/high-risk tokens using Stealth Chrome MCP.
        Uses fingerprint randomization and proxy chaining for anonymity.
        """
        targets = []
        try:
            # 1. Navigate to Token Sniffer trending page
            nav_result = await self.stealth.navigate_stealth(
                url="https://tokensniffer.com/tokens/trending?risk=high",
                wait_until="networkidle",
                randomize_fingerprint=True,
                proxy_chain="residential"
            )
            print(f"[INTEL] Stealth navigate: {nav_result.get('status')}")

            # 2. Extract structured data from the page
            extracted = await self.stealth.extract_structured(
                schema={
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "address": {"type": "string", "description": "Token contract address"},
                            "name": {"type": "string"},
                            "symbol": {"type": "string"},
                            "risk_score": {"type": "integer"},
                            "chain": {"type": "string"}
                        }
                    }
                },
                selector="table.token-table tbody tr"
            )
            for item in extracted.get("data", []):
                targets.append({
                    "address": item["address"],
                    "chain": item.get("chain", "ethereum_mainnet"),
                    "source": "tokensniffer",
                    "risk_score": item.get("risk_score", 0),
                    "metadata": {"name": item.get("name"), "symbol": item.get("symbol")}
                })

            print(f"[INTEL] Token Sniffer (stealth): {len(targets)} targets")
            return targets

        except Exception as e:
            print(f"[INTEL] Stealth scrape failed: {e}")
            return []

    async def _scrape_dune(self) -> List[Dict]:
        """Pull proxy tax targets from Dune Analytics"""
        try:
            page = await self.hb.scrape_webpage(
                url="https://dune.com/queries/proxy-tax-detection",
                format="html"
            )
            addresses = self._extract_eth_addresses(page)
            return [
                {
                    "address": addr,
                    "chain": "unknown",
                    "source": "dune",
                    "risk_tags": ["proxy", "tax_suspicious"],
                    "timestamp": datetime.utcnow().isoformat()
                }
                for addr in addresses
            ]
        except Exception as e:
            print(f"Dune scrape failed: {e}")
            return []

    async def _scrape_bscscan_unverified(self) -> List[Dict]:
        """Pull unverified tokens from BscScan"""
        try:
            page = await self.hb.scrape_webpage(
                url="https://bscscan.com/tokens?filter=0&sort=unverified",
                format="html"
            )
            # Extract addresses from table rows
            addresses = self._parse_bscscan_table(page)
            return [
                {
                    "address": addr,
                    "chain": "bsc_mainnet",
                    "source": "bscscan_unverified",
                    "risk_tags": ["unverified"],
                    "timestamp": datetime.utcnow().isoformat()
                }
                for addr in addresses
            ]
        except Exception as e:
            print(f"BscScan scrape failed: {e}")
            return []

    async def _scrape_etherscan_proxies(self) -> List[Dict]:
        """Pull proxy contracts from Etherscan"""
        try:
            page = await self.hb.scrape_webpage(
                url="https://etherscan.io/proxycontracts",
                format="html"
            )
            addresses = self._parse_etherscan_proxy_table(page)
            return [
                {
                    "address": addr,
                    "chain": "ethereum_mainnet",
                    "source": "etherscan_proxies",
                    "risk_tags": ["proxy"],
                    "timestamp": datetime.utcnow().isoformat()
                }
                for addr in addresses
            ]
        except Exception as e:
            print(f"Etherscan proxy scrape failed: {e}")
            return []

    async def _web_search_threat_intel(self) -> List[Dict]:
        """Search for articles about proxy tax vulnerabilities"""
        queries = [
            "upgradeable proxy erc20 tax dormant hook",
            "unverified BSC token with mint function",
            "token proxy upgrade attack vector",
        ]
        results = []
        for query in queries:
            search_results = await self.web.web_search(query=query)
            for result in search_results[:5]:  # top 5 per query
                page = await self.web.fetch_webpage(url=result["url"])
                addresses = self._extract_eth_addresses(page)
                for addr in addresses:
                    results.append({
                        "address": addr,
                        "chain": "unknown",
                        "source": "web_search",
                        "query": query,
                        "timestamp": datetime.utcnow().isoformat()
                    })
        return results

    def _parse_bscscan_table(self, html: str) -> List[str]:
        """Extract contract addresses from BscScan HTML table"""
        import re
        # Pattern: 0x followed by 40 hex characters
        pattern = r'0x[a-fA-F0-9]{40}'
        return list(set(re.findall(pattern, html)))

    def _parse_etherscan_proxy_table(self, html: str) -> List[str]:
        """Extract proxy contract addresses from Etherscan HTML"""
        import re
        pattern = r'0x[a-fA-F0-9]{40}'
        return list(set(re.findall(pattern, html)))

    def _extract_eth_addresses(self, text: str) -> List[str]:
        """Extract Ethereum addresses from arbitrary text"""
        import re
        pattern = r'0x[a-fA-F0-9]{40}'
        return list(set(re.findall(pattern, text)))

    def _deduplicate(self, targets: List[Dict]) -> List[Dict]:
        """Remove duplicate addresses, keeping the most informative entry"""
        seen = {}
        for t in targets:
            key = f"{t['address']}_{t['chain']}"
            if key not in seen:
                seen[key] = t
            else:
                # Merge risk tags
                existing = seen[key]
                existing["risk_tags"] = list(set(existing.get("risk_tags", []) + t.get("risk_tags", [])))
                existing["source"] = f"{existing['source']},{t['source']}"
        return list(seen.values())

    async def _persist(self, targets: List[Dict]):
        """Store intel in bucket"""
        await self.store.write_file(
            f"redteam/intel/target_list_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
            json.dumps({"targets": targets, "count": len(targets)})
        )
