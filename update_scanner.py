import re

with open("src/scanner.py", "r") as f:
    content = f.read()

# Fix ABI
abi_search = '{"internalType": "bool", "name": "isProxy", "type": "bool"},'
abi_replace = '{"internalType": "bool", "name": "isProxy", "type": "bool"},\n                    {"internalType": "uint8", "name": "proxyType", "type": "uint8"},'
content = content.replace(abi_search, abi_replace)

# Fix Decoding
decode_search = """            base = 2 + i * 576  # 9 fields × 64 hex chars
            raw = result[base:base + 576]
            risk_score = int(raw[-64:], 16) if raw[-64:] else 0
            scanned.append({
                "address": target["address"],
                "chain": target["chain"],
                "source": target.get("source", "unknown"),
                "isProxy": raw[0:64] != "0" * 64,
                "implAddress": "0x" + raw[64:128][-40:],
                "riskScore": risk_score,"""

decode_replace = """            base = 2 + i * 640  # 10 fields × 64 hex chars
            raw = result[base:base + 640]
            
            is_proxy = raw[64:128] != "0" * 64
            p_type_int = int(raw[128:192], 16) if raw[128:192] else 0
            proxy_types = {0: "NONE", 1: "EIP-1967", 2: "UUPS", 3: "Transparent", 4: "Beacon"}
            p_type_str = proxy_types.get(p_type_int, "Unknown")
            
            impl_addr = "0x" + raw[192:256][-40:]
            has_before = raw[256:320] != "0" * 64
            has_after = raw[320:384] != "0" * 64
            has_tax = raw[384:448] != "0" * 64
            has_set_fee = raw[448:512] != "0" * 64
            has_mint = raw[512:576] != "0" * 64
            risk_score = int(raw[576:640], 16) if raw[576:640] else 0
            
            scanned.append({
                "address": target["address"],
                "chain": target["chain"],
                "source": target.get("source", "unknown"),
                "isProxy": is_proxy,
                "proxyType": p_type_str,
                "implAddress": impl_addr,
                "hasBeforeTokenTransferHook": has_before,
                "hasAfterTokenTransferHook": has_after,
                "hasTaxPercentVariable": has_tax,
                "hasSetFeeFunction": has_set_fee,
                "hasMintFunction": has_mint,
                "riskScore": risk_score,"""

content = content.replace(decode_search, decode_replace)

with open("src/scanner.py", "w") as f:
    f.write(content)
