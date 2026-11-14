#!/usr/bin/env python3
"""Jesshq Guard — wallet & transaction guard agent (core logic).

Screens a smart contract (and, optionally, a wallet's approvals to it)
BEFORE the user signs anything. Read-only: it never signs, sends, or
spends. It returns facts plus a scored verdict so a beginner can decide
whether to approve, mint, or walk away.

Checks (BSC chain 56 by default; any EVM chain id works for the
Sourcify lookup and for RPCs that serve that chain):
  1. The address holds contract code (eth_getCode).
  2. Source verified on Sourcify (exact / partial / none) + contract name.
  3. Owner-power functions exposed by the ABI (withdraw, pause,
     setBaseURI, transferOwnership, mint, renounceOwnership).
  4. Optional: ERC-20 allowance of `wallet` to `spender`, and
     isApprovedForAll(owner=wallet, operator=spender) for NFTs.

Scoring (100-point, start at 100, deduct):
  no code                      -> verdict AVOID, score 0 (hard fail)
  source not verified          -> -30
  partial Sourcify match       -> -15
  withdraw()                   -> -15
  setBaseURI()/setTokenURI()   -> -10
  pause()                      -> -5
  transferOwnership()          -> -5
  owner mint()                 -> -5
  unlimited ERC-20 allowance   -> -20
  isApprovedForAll == true     -> -20

Verdict: score >= 70 SAFE, 40-69 REVIEW, < 40 AVOID.
A verdict is a screening aid, not a guarantee: a verified contract can
still be malicious, and an unverified one is not automatically a scam.

Stdlib only (urllib). No API keys, no secrets, no signing.
"""

import json
import urllib.error
import urllib.request

USER_AGENT = "jesshq-guard/1.0 (zkverify-agent-games-wildcard)"

DEFAULT_RPCS = {
    56: [
        "https://bsc-dataseed.bnbchain.org",
        "https://bsc.publicnode.com",
        "https://bsc-dataseed1.bnbchain.org",
    ],
    1: ["https://ethereum-rpc.publicnode.com"],
    8453: ["https://base-rpc.publicnode.com", "https://mainnet.base.org"],
}
SOURCIFY_API = "https://sourcify.dev/server/v2/contract"

# Owner-power functions worth flagging. Presence alone is NOT proof of
# malicious intent -- many legitimate contracts have them -- but they
# are the levers an owner can abuse, so the user should know they exist.
WATCH_FUNCTIONS = {
    "withdraw": ("owner can withdraw funds held by the contract", 15),
    "setBaseURI": ("owner can change token metadata URIs", 10),
    "setTokenURI": ("owner can change a token metadata URI", 10),
    "pause": ("owner can pause transfers/mints", 5),
    "transferOwnership": ("owner can hand control to another address", 5),
    "mint": ("owner can create new tokens", 5),
}

SEL_ALLOWANCE = "dd62ed3e"    # allowance(address,address)
SEL_IS_APPROVED = "e985e9c5"  # isApprovedForAll(address,address)
SEL_DECIMALS = "313ce567"     # decimals()
SEL_SYMBOL = "95d89b41"       # symbol()

MAX_UINT256 = (1 << 256) - 1


def _http_json(url, timeout=25):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def _rpc(rpcs, method, params, timeout=25):
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    ).encode()
    last_err = None
    for rpc in rpcs:
        for _ in range(2):
            try:
                req = urllib.request.Request(
                    rpc, data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": USER_AGENT,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    out = json.load(resp)
                if "error" in out:
                    last_err = out["error"].get("message", "RPC error")
                    break
                return out.get("result")
            except Exception as e:  # noqa: BLE001 - try next endpoint
                last_err = str(e)
                continue
    raise RuntimeError(f"all RPC endpoints failed ({last_err})")


def _call(rpcs, to, data):
    return _rpc(rpcs, "eth_call", [{"to": to, "data": data}, "latest"])


def _pad_address(address):
    return "000000000000000000000000" + address[2:].lower()


def _decode_uint(hex_data):
    if not hex_data or hex_data == "0x":
        return 0
    return int(hex_data, 16)


def _decode_string(hex_data):
    if not hex_data or hex_data == "0x":
        return "?"
    raw = bytes.fromhex(hex_data[2:])
    if len(raw) < 96:
        return "?"
    length = int.from_bytes(raw[32:64], "big")
    try:
        return raw[64:64 + length].decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return "?"


def _sourcify(address, chain_id):
    """Return (match, abi, contract_name); match is None when unverified."""
    base = f"{SOURCIFY_API}/{chain_id}/{address}"
    try:
        status = _http_json(base)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None, None, None
        raise RuntimeError(f"Sourcify HTTP {e.code}")
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"Sourcify unreachable: {e}")
    match = status.get("match", "unknown")
    abi = None
    name = None
    try:
        abi = _http_json(base + "?fields=abi").get("abi")
    except Exception:  # noqa: BLE001 - ABI is nice to have, not fatal
        abi = None
    try:
        meta = _http_json(base + "?fields=metadata")
        settings = (meta.get("metadata") or {}).get("settings", {})
        target = settings.get("compilationTarget", {})
        if isinstance(target, dict) and target:
            name = next(iter(target.values()), None)
    except Exception:  # noqa: BLE001 - name is nice to have, not fatal
        name = None
    return match, abi, name


def _abi_function_names(abi):
    names = set()
    for item in abi or []:
        if item.get("type") == "function" and item.get("name"):
            names.add(item["name"])
    return names


def screen(contract, wallet=None, spender=None, chain_id=56, rpcs=None):
    """Screen a contract. Returns a dict with verdict, score, checks."""
    if not (contract.startswith("0x") and len(contract) == 42):
        raise ValueError("contract must be a 0x address (42 characters)")
    rpcs = rpcs or DEFAULT_RPCS.get(chain_id) or DEFAULT_RPCS[56]

    checks = []
    score = 100

    # 1. Contract code present?
    code = _rpc(rpcs, "eth_getCode", [contract, "latest"])
    has_code = bool(code and code != "0x")
    checks.append({
        "id": "code_exists",
        "passed": has_code,
        "detail": "Contract code exists on-chain."
        if has_code else "No code at this address. Wrong address, wrong "
        "chain, or the contract is not deployed.",
    })
    if not has_code:
        return {
            "contract": contract, "chain": chain_id, "verdict": "AVOID",
            "score": 0, "checks": checks, "risks": [
                "No contract code at this address."
            ],
            "explanation": "There is no contract at this address on this "
            "chain. Do not approve, mint, or send anything to it.",
        }

    # 2. Sourcify verification.
    match, abi, name = _sourcify(contract, chain_id)
    if match is None:
        score -= 30
        checks.append({
            "id": "sourcify_verified", "passed": False,
            "detail": "Source NOT verified on Sourcify. You cannot read "
            "what this contract does.",
        })
    else:
        if match == "partial":
            score -= 15
        checks.append({
            "id": "sourcify_verified", "passed": True,
            "detail": f"Source verified on Sourcify (match: {match})."
            + (f" Contract name: {name}." if name else ""),
        })

    # 3. Owner-power functions from the ABI.
    risks = []
    if abi is None:
        checks.append({
            "id": "abi_functions", "passed": False,
            "detail": "No ABI available, cannot list functions. Without "
            "source code you cannot verify what the contract does.",
        })
    else:
        names = _abi_function_names(abi)
        found = {}
        for fn, (meaning, deduction) in WATCH_FUNCTIONS.items():
            if fn in names:
                found[fn] = meaning
                score -= deduction
                risks.append(f"{fn}(): {meaning}.")
        checks.append({
            "id": "abi_functions", "passed": True,
            "detail": f"Contract exposes {len(names)} functions."
            + ("" if not found else " Owner-power functions found: "
               + ", ".join(sorted(found)) + "."),
        })
        if "renounceOwnership" in names:
            score = min(100, score + 5)
            checks.append({
                "id": "renounce_ownership", "passed": True,
                "detail": "renounceOwnership exists (owner can give up "
                "control). Good sign.",
            })

    # 4. Optional wallet approval checks.
    if wallet and spender:
        if not (wallet.startswith("0x") and len(wallet) == 42):
            raise ValueError("wallet must be a 0x address (42 characters)")
        if not (spender.startswith("0x") and len(spender) == 42):
            raise ValueError("spender must be a 0x address (42 characters)")
        data = ("0x" + SEL_ALLOWANCE + _pad_address(wallet)
                + _pad_address(spender))
        amount = _decode_uint(_call(rpcs, contract, data))
        if amount == MAX_UINT256:
            score -= 20
            risks.append("Wallet gave this spender an UNLIMITED token "
                         "allowance. It can drain the token balance.")
            checks.append({
                "id": "erc20_allowance", "passed": False,
                "detail": "UNLIMITED ERC-20 allowance from wallet to "
                "spender. Revoke it if you did not intend this.",
            })
        elif amount > 0:
            checks.append({
                "id": "erc20_allowance", "passed": True,
                "detail": f"ERC-20 allowance is limited (raw {amount}).",
            })
        else:
            checks.append({
                "id": "erc20_allowance", "passed": True,
                "detail": "No ERC-20 allowance from wallet to spender.",
            })
        data = ("0x" + SEL_IS_APPROVED + _pad_address(wallet)
                + _pad_address(spender))
        approved = _decode_uint(_call(rpcs, contract, data)) != 0
        if approved:
            score -= 20
            risks.append("Wallet approved this operator for ALL of its "
                         "NFTs (isApprovedForAll). It can move every NFT.")
            checks.append({
                "id": "nft_approval", "passed": False,
                "detail": "isApprovedForAll is TRUE: operator can move "
                "all NFTs of this wallet. Revoke it if unintended.",
            })
        else:
            checks.append({
                "id": "nft_approval", "passed": True,
                "detail": "No blanket NFT approval for this operator.",
            })

    score = max(0, min(100, score))
    # An unverified contract can never be SAFE: without source code the
    # user cannot read what the contract does, no matter the other checks.
    if match is None:
        score = min(score, 69)
    verdict = "SAFE" if score >= 70 else ("REVIEW" if score >= 40 else "AVOID")
    explanation = {
        "SAFE": "No major red flags found in the checks above. The "
        "contract exists, its source is readable, and no dangerous "
        "owner powers or unlimited approvals were found. Still verify "
        "the project itself (website, team, community) before signing.",
        "REVIEW": "Some caution flags were found. Read the risks above "
        "and understand them before you approve or mint. If anything "
        "is unclear, do not sign.",
        "AVOID": "Serious red flags. Do not approve, mint, or send "
        "anything to this contract until every risk above is explained "
        "by the project itself.",
    }[verdict]

    return {
        "contract": contract, "chain": chain_id, "verdict": verdict,
        "score": score, "checks": checks, "risks": risks,
        "explanation": explanation,
    }


if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Jesshq Guard (read-only).")
    parser.add_argument("contract", help="contract address (0x...)")
    parser.add_argument("--wallet", help="wallet address to check approvals")
    parser.add_argument("--spender", help="spender/operator address")
    parser.add_argument("--chain", type=int, default=56)
    args = parser.parse_args()
    result = screen(args.contract, args.wallet, args.spender, args.chain)
    print(json.dumps(result, indent=2))
