import asyncio
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import aiohttp
import yaml
from dotenv import load_dotenv

load_dotenv()

ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


@dataclass(frozen=True)
class IntelTarget:
    contract_address: str
    chain: str
    source: str
    confidence: str = "medium"
    metadata: Optional[Dict[str, Any]] = None


class _RateLimiter:
    def __init__(self, rps: float) -> None:
        self._interval = 1 / rps if rps and rps > 0 else 0
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def wait(self) -> None:
        if self._interval <= 0:
            return
        async with self._lock:
            now = asyncio.get_running_loop().time()
            delay = self._last + self._interval - now
            if delay > 0:
                await asyncio.sleep(delay)
            self._last = asyncio.get_running_loop().time()


class IntelGatherer:
    """Phase 1 reconnaissance gatherer (OSINT + read-only live pull)."""

    def __init__(
        self,
        hb_client: Any,
        web_client: Any,
        store_client: Any,
        config_dir: str = "config",
        session: Optional[aiohttp.ClientSession] = None,
    ) -> None:
        self.hb_client = hb_client
        self.web_client = web_client
        self.store_client = store_client
        self._config_dir = Path(config_dir)
        self._session = session
        self._owned_session: Optional[aiohttp.ClientSession] = None

        self.profile = self._read_yaml("redteam_profile.yaml")
        self.chains = self._read_yaml("chains.yaml").get("chains", {})
        self.mcp = self._read_yaml("mcp_servers.yaml").get("servers", {})

        operation = self.profile.get("operation", {})
        recon = operation.get("mainnet_recon", {})
        self._target_chains: Sequence[str] = operation.get("target_chains", [])
        self._max_contracts = int(recon.get("max_contracts_per_scan", 1000))
        self._recon_enabled = bool(recon.get("enabled", True))
        self._read_only = bool(recon.get("read_only", True))
        self._limiter = _RateLimiter(float(recon.get("rate_limit_rps", 5)))

        controlled_execution = operation.get("controlled_execution", {}).get("enabled", False)
        if controlled_execution:
            raise ValueError("Phase 1 requires controlled_execution.enabled=false")

    def _read_yaml(self, file_name: str) -> Dict[str, Any]:
        with (self._config_dir / file_name).open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session and not self._session.closed:
            return self._session
        if self._owned_session and not self._owned_session.closed:
            return self._owned_session
        self._owned_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30))
        return self._owned_session

    async def close(self) -> None:
        if self._owned_session and not self._owned_session.closed:
            await self._owned_session.close()

    async def verify_mcp_connections(self) -> Dict[str, bool]:
        return {
            "hyperbrowser_mcp": await self._ping_client(self.hb_client),
            "web_fetch_mcp": await self._ping_client(self.web_client),
            "bucket_store_mcp": await self._ping_client(self.store_client),
        }

    async def _ping_client(self, client: Any) -> bool:
        for method_name in ("ping", "health", "healthcheck", "ready"):
            method = getattr(client, method_name, None)
            if callable(method):
                result = method()
                if asyncio.iscoroutine(result):
                    result = await result
                return bool(result if result is not None else True)
        return client is not None

    async def gather_all(self) -> List[Dict[str, Any]]:
        if not self._recon_enabled:
            return []
        if not self._read_only:
            raise RuntimeError("Phase 1 must run in read-only mode")

        health = await self.verify_mcp_connections()
        if not all(health.values()):
            failed = [name for name, ok in health.items() if not ok]
            raise RuntimeError(f"MCP connectivity check failed: {', '.join(failed)}")

        targets = await self._collect_targets()
        deduped = self._dedupe_targets(targets)

        payload = {
            "operation": self.profile.get("operation", {}).get("name", "proxy-strike-phase-1"),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mcp_health": health,
            "target_count": len(deduped),
            "targets": [asdict(t) for t in deduped],
        }

        await self._write_target_list(payload)
        return payload["targets"]

    async def _collect_targets(self) -> List[IntelTarget]:
        osint_task = self._gather_osint()
        live_task = self._gather_live_pull()
        osint_targets, live_targets = await asyncio.gather(osint_task, live_task)
        return [*osint_targets, *live_targets]

    async def _gather_osint(self) -> List[IntelTarget]:
        urls = [
            ("tokensniffer", "https://tokensniffer.com/tokens/scam"),
            ("bscscan", "https://bscscan.com/tokens?ps=100&p=1"),
        ]

        collected: List[IntelTarget] = []
        for source, url in urls:
            await self._limiter.wait()
            text = await self._fetch_text(url)
            for address in self._extract_addresses(text):
                collected.append(
                    IntelTarget(
                        contract_address=address,
                        chain="bsc_mainnet" if source == "bscscan" else "ethereum_mainnet",
                        source=f"osint:{source}",
                        confidence="medium",
                    )
                )

        return collected[: self._max_contracts]

    async def _gather_live_pull(self) -> List[IntelTarget]:
        targets: List[IntelTarget] = []
        for chain in self._target_chains:
            chain_config = self.chains.get(chain)
            if not chain_config:
                continue
            await self._limiter.wait()
            discovered = await self._discover_chain_contracts(chain, chain_config)
            targets.extend(discovered)
            if len(targets) >= self._max_contracts:
                break
        return targets[: self._max_contracts]

    async def _discover_chain_contracts(self, chain: str, chain_config: Dict[str, Any]) -> List[IntelTarget]:
        for method_name in ("discover_proxy_contracts", "scan_proxy_contracts", "list_proxy_contracts"):
            method = getattr(self.hb_client, method_name, None)
            if callable(method):
                result = method(chain=chain, rpc=chain_config.get("rpc"), limit=self._max_contracts)
                if asyncio.iscoroutine(result):
                    result = await result
                return self._normalize_hb_results(result or [], chain)
        return []

    def _normalize_hb_results(self, result: Iterable[Any], chain: str) -> List[IntelTarget]:
        normalized: List[IntelTarget] = []
        for item in result:
            if isinstance(item, str):
                address = item
                metadata: Dict[str, Any] = {}
            elif isinstance(item, dict):
                address = item.get("address") or item.get("contract") or ""
                metadata = {k: v for k, v in item.items() if k not in {"address", "contract"}}
            else:
                continue

            if not ADDRESS_RE.fullmatch(address):
                continue

            normalized.append(
                IntelTarget(
                    contract_address=address,
                    chain=chain,
                    source="live_pull:hyperbrowser",
                    confidence="high",
                    metadata=metadata or None,
                )
            )
        return normalized

    async def _fetch_text(self, url: str) -> str:
        fetch = getattr(self.web_client, "fetch", None)
        if callable(fetch):
            response = fetch(url=url)
            if asyncio.iscoroutine(response):
                response = await response
            if isinstance(response, dict):
                return str(response.get("content") or response.get("text") or "")
            return str(response or "")

        session = await self._get_session()
        async with session.get(url) as resp:
            return await resp.text()

    def _extract_addresses(self, text: str) -> List[str]:
        if not text:
            return []
        found = ADDRESS_RE.findall(text)
        seen = set()
        unique = []
        for address in found:
            lowered = address.lower()
            if lowered in seen:
                continue
            seen.add(lowered)
            unique.append(address)
        return unique

    def _dedupe_targets(self, targets: Iterable[IntelTarget]) -> List[IntelTarget]:
        seen = set()
        deduped = []
        for target in targets:
            key = (target.chain, target.contract_address.lower())
            if key in seen:
                continue
            seen.add(key)
            deduped.append(target)
        return deduped

    async def _write_target_list(self, payload: Dict[str, Any]) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        key = f"redteam/intel/target_list_{ts}.json"

        for method_name in ("put_json", "write_json", "upload_json", "put_object"):
            method = getattr(self.store_client, method_name, None)
            if callable(method):
                if method_name == "put_object":
                    result = method(key=key, content=json.dumps(payload), content_type="application/json")
                else:
                    result = method(key=key, value=payload)
                if asyncio.iscoroutine(result):
                    await result
                return

        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / Path(key).name).write_text(json.dumps(payload, indent=2), encoding="utf-8")
