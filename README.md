# PROXY-STRIKE Red Team Fortification System

## ⚠️ LEGAL NOTICE
This system is designed exclusively for authorized security testing and 
fortification of your own assets or assets you have explicit permission to test. 
Unauthorized use against mainnet contracts is illegal and unethical.

## Capabilities
- **Mainnet Reconnaissance**: Read-only scanning of contracts for proxy/tax vulnerabilities
- **Controlled Exploitation**: Execute attack chains ONLY on authorized test networks
- **Continuous Monitoring**: 24/7 watchtower for proxy implementation changes
- **Automated Fortification**: Deploy TaxImmuneWrapper and UpgradeMonitor defenses

## Quick Start
```bash
# 1. Configure target chains
vim config/chains.yaml

# 2. Start the system
docker-compose up -d

# 3. Monitor logs
docker-compose logs -f proxy-strike

# 4. Retrieve reports
ls reports/
```

## Phases
- Intelligence Gathering - Scrape token sniffer, BscScan, Etherscan
- Vulnerability Scanning - Deploy scanner, batch scan targets
- Controlled Exploit - Execute OMENX attack chain on testnet
- Watchtower - Continuous monitoring daemon
- Fortification - Deploy defensive wrappers and monitors

## Configuration
Edit config/redteam_profile.yaml to enable/disable mainnet recon and controlled execution.

## Output
All reports and alerts are stored in the Hugging Face bucket:

- redteam/intel/target_list_*.json
- redteam/scans/scan_*.json
- redteam/reports/exploit_*.json
- redteam/reports/fortification_*.json
- redteam/alerts/*.json

---

## 8. DEPLOYMENT SEQUENCE

```bash
# 1. Clone and enter the system
mkdir proxy-strike && cd proxy-strike
# (copy all files above into this directory)

# 2. Configure MCP endpoints
vim config/mcp_servers.yaml

# 3. Set operation parameters
vim config/redteam_profile.yaml
# Set mode: production
# Set mainnet_recon.enabled: true
# Set controlled_execution.enabled: true (gated to testnets)

# 4. Build and launch
docker-compose build
docker-compose up -d

# 5. Verify engagement
docker-compose logs -f proxy-strike
# Look for: "[PROXY-STRIKE] Engagement ... complete!"

# 6. Extract reports
docker-compose exec proxy-strike ls /app/reports/
```

This is the complete, uncompromised Red Team system. Every component is configured for mainnet reconnaissance and controlled execution on authorized networks. The system is fully quarantined within Docker, with all MCP connections mapped to your internal endpoints.
