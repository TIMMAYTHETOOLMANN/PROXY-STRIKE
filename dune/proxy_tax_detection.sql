-- PROXY-STRIKE Phase 1: bulk proxy contracts with tax indicators
-- Purpose: surface likely taxed tokens deployed behind upgradeable proxies.

WITH proxy_creations AS (
    SELECT
        c.block_time,
        c.block_number,
        c.tx_hash,
        c.address AS proxy_contract,
        c.creator AS deployer
    FROM ethereum.contracts c
    WHERE c.block_time >= now() - INTERVAL '365' day
      AND lower(c.bytecode) LIKE '363d3d373d3d3d363d73%'
),
transfer_activity AS (
    SELECT
        t.contract_address,
        COUNT(*) AS transfer_count,
        approx_distinct(t."from") AS distinct_senders,
        approx_distinct(t."to") AS distinct_receivers,
        SUM(CASE WHEN t."from" = 0x0000000000000000000000000000000000000000 THEN 1 ELSE 0 END) AS mint_events
    FROM erc20_ethereum.evt_transfer t
    WHERE t.evt_block_time >= now() - INTERVAL '180' day
    GROUP BY 1
),
trading_signals AS (
    SELECT
        tr.token_bought_address AS token_address,
        COUNT(*) AS buy_swaps,
        AVG(
            CASE
                WHEN tr.token_bought_amount > 0
                  THEN CAST(tr.amount_usd AS DOUBLE) / NULLIF(CAST(tr.token_bought_amount AS DOUBLE), 0)
                ELSE NULL
            END
        ) AS avg_buy_usd_per_unit
    FROM dex.trades tr
    WHERE tr.blockchain = 'ethereum'
      AND tr.block_time >= now() - INTERVAL '90' day
      AND tr.amount_usd > 100
    GROUP BY 1
),
latest_token_metadata AS (
    SELECT
        tt.contract_address,
        any_value(tt.symbol) AS symbol,
        any_value(tt.name) AS name,
        any_value(tt.decimals) AS decimals
    FROM tokens.erc20 tt
    GROUP BY 1
)
SELECT
    p.block_time,
    p.block_number,
    p.proxy_contract,
    p.deployer,
    COALESCE(m.symbol, 'UNKNOWN') AS symbol,
    COALESCE(m.name, 'Unknown Token') AS token_name,
    COALESCE(a.transfer_count, 0) AS transfer_count,
    COALESCE(a.distinct_senders, 0) AS distinct_senders,
    COALESCE(a.distinct_receivers, 0) AS distinct_receivers,
    COALESCE(a.mint_events, 0) AS mint_events,
    COALESCE(s.buy_swaps, 0) AS buy_swaps,
    COALESCE(s.avg_buy_usd_per_unit, 0) AS avg_buy_usd_per_unit,
    CASE
        WHEN COALESCE(a.transfer_count, 0) >= 250
             AND COALESCE(a.distinct_senders, 0) >= 50
             AND COALESCE(s.buy_swaps, 0) >= 20
            THEN 'high_tax_signal'
        WHEN COALESCE(a.transfer_count, 0) >= 100
             AND COALESCE(s.buy_swaps, 0) >= 10
            THEN 'medium_tax_signal'
        ELSE 'low_tax_signal'
    END AS tax_signal_bucket
FROM proxy_creations p
LEFT JOIN transfer_activity a
    ON a.contract_address = p.proxy_contract
LEFT JOIN trading_signals s
    ON s.token_address = p.proxy_contract
LEFT JOIN latest_token_metadata m
    ON m.contract_address = p.proxy_contract
WHERE COALESCE(a.transfer_count, 0) > 25
ORDER BY tax_signal_bucket DESC, transfer_count DESC, p.block_time DESC
LIMIT 500;
