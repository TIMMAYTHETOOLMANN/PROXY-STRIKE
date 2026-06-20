-- PROXY-STRIKE: Bulk Detection of Upgradeable Proxy Tokens with Tax Capability
-- Runs across Ethereum, Polygon, Arbitrum, Optimism, BSC

WITH proxy_contracts AS (
  SELECT 
    address,
    blockchain,
    implementation_address
  FROM (
    -- Ethereum
    SELECT address, 'ethereum' as blockchain, 
           bytearray_substring(data, 13, 20) as implementation_address
    FROM ethereum.storage_reads
    WHERE slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
      AND bytearray_length(data) = 32
    UNION ALL
    -- Polygon
    SELECT address, 'polygon' as blockchain,
           bytearray_substring(data, 13, 20) as implementation_address
    FROM polygon.storage_reads
    WHERE slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
      AND bytearray_length(data) = 32
    UNION ALL
    -- Arbitrum
    SELECT address, 'arbitrum' as blockchain,
           bytearray_substring(data, 13, 20) as implementation_address
    FROM arbitrum.storage_reads
    WHERE slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
      AND bytearray_length(data) = 32
    UNION ALL
    -- Optimism
    SELECT address, 'optimism' as blockchain,
           bytearray_substring(data, 13, 20) as implementation_address
    FROM optimism.storage_reads
    WHERE slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
      AND bytearray_length(data) = 32
    UNION ALL
    -- BSC
    SELECT address, 'bsc' as blockchain,
           bytearray_substring(data, 13, 20) as implementation_address
    FROM bnb.storage_reads
    WHERE slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
      AND bytearray_length(data) = 32
  )
),

tax_suspicious_bytecode AS (
  -- Selectors that indicate tax capability
  SELECT 
    address,
    blockchain,
    bytecode
  FROM (
    SELECT address, 'ethereum' as blockchain, bytecode FROM ethereum.contracts
    UNION ALL
    SELECT address, 'polygon' as blockchain, bytecode FROM polygon.contracts
    UNION ALL
    SELECT address, 'arbitrum' as blockchain, bytecode FROM arbitrum.contracts
    UNION ALL
    SELECT address, 'optimism' as blockchain, bytecode FROM optimism.contracts
    UNION ALL
    SELECT address, 'bsc' as blockchain, bytecode FROM bnb.contracts
  )
  WHERE bytecode IS NOT NULL
    AND (
      -- setTaxPercent(uint256)
      bytecode LIKE '%4aee6ffc%'
      -- setFee(uint256)
      OR bytecode LIKE '%69fe0e2d%'
      -- enableTax()
      OR bytecode LIKE '%2e1a7d4d%'
      -- _beforeTokenTransfer
      OR bytecode LIKE '%9d0f3c6a%'
      -- _afterTokenTransfer
      OR bytecode LIKE '%2d93e1e9%'
      -- mint(address,uint256)
      OR bytecode LIKE '%40c10f19%'
    )
)

SELECT DISTINCT
  pc.address AS proxy_address,
  pc.blockchain,
  pc.implementation_address,
  CASE 
    WHEN tb.bytecode LIKE '%4aee6ffc%' THEN 'setTaxPercent'
    WHEN tb.bytecode LIKE '%69fe0e2d%' THEN 'setFee'
    WHEN tb.bytecode LIKE '%2e1a7d4d%' THEN 'enableTax'
    WHEN tb.bytecode LIKE '%9d0f3c6a%' THEN 'beforeTokenTransferHook'
    WHEN tb.bytecode LIKE '%2d93e1e9%' THEN 'afterTokenTransferHook'
    WHEN tb.bytecode LIKE '%40c10f19%' THEN 'mintFunction'
  END AS risk_indicator
FROM proxy_contracts pc
JOIN tax_suspicious_bytecode tb 
  ON pc.implementation_address = tb.address 
  AND pc.blockchain = tb.blockchain
ORDER BY pc.blockchain, pc.address;
