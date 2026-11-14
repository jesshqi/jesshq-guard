# Jesshq Guard — Wallet & Transaction Guard Agent

A read-only agent that screens a smart contract (and, optionally, a
wallet's approvals to it) **before** you sign anything. It returns facts
plus a scored verdict, so a beginner can decide whether to approve,
mint, or walk away.

Built for the **zkVerify Agent Games 2026 — Wildcard track** (wallet &
transaction guard use case).

## The problem

Before you mint a "free" NFT or approve a contract, you have to answer
three questions:

1. Is there really a contract at this address?
2. Can anyone read what the contract does — or is the source hidden?
3. Did you (or the contract) already hand over dangerous permissions?

Most people answer these by trust: a link from a friend, a nice-looking
website, a countdown timer. Scams, honeypots, and unlimited approvals
live exactly in that gap. Jesshq Guard closes it with on-chain facts:
it reads the chain and Sourcify, then shows you the evidence.

## Who it helps

- **Beginners** minting their first free NFT, who cannot read Solidity.
- **AI agents** that mint, claim, or approve on a user's behalf and need
  a pre-flight check before they sign.
- **Anyone** who has ever approved a contract and later wondered what
  they actually approved.

## What it does

`POST /api/screen` with a contract address (and, optionally, a wallet
and a spender) returns:

```json
{
  "contract": "0xA74081fd9bc9623A2d9321223C35b41016A7fd65",
  "chain": 56,
  "verdict": "SAFE",
  "score": 100,
  "checks": [
    {"id": "code_exists", "passed": true,
     "detail": "Contract code exists on-chain."},
    {"id": "sourcify_verified", "passed": true,
     "detail": "Source verified on Sourcify (match: exact_match)."},
    {"id": "abi_functions", "passed": true,
     "detail": "Contract exposes 76 functions."}
  ],
  "risks": ["transferOwnership(): owner can hand control to another address."],
  "explanation": "No major red flags found in the checks above..."
}
```

Checks:

1. **Contract code** — `eth_getCode`. No code means wrong address,
   wrong chain, or no deployment. Hard fail: verdict AVOID, score 0.
2. **Sourcify verification** — exact / partial / none, plus the
   contract name when available. An unverified contract can never
   score SAFE: without source code you cannot read what it does.
3. **Owner-power functions** — from the ABI when verified: `withdraw`,
   `pause`, `setBaseURI`/`setTokenURI`, `transferOwnership`, `mint`.
   Presence is not proof of malice, but the user should know these
   levers exist before signing.
4. **Wallet approvals (optional)** — ERC-20 `allowance` (flags
   unlimited) and ERC-721/1155 `isApprovedForAll` for a given wallet
   and spender/operator.

Scoring is a 100-point scale: start at 100, deduct per finding
(unverified source −30, `withdraw` −15, unlimited allowance −20,
blanket NFT approval −20, and so on). Verdict: ≥70 SAFE, 40–69 REVIEW,
<40 AVOID.

## What it can and cannot do

- **Can:** show on-chain facts and score them consistently.
- **Cannot:** guarantee a contract is safe. A verified contract can
  still be malicious, and an unverified one is not automatically a
  scam. Always check the project itself — website, team, community —
  alongside this screen.
- **Never:** signs, sends, or spends anything. Read-only by design.
  No wallet, no private key, no API key.

## How it works

- `guard.py` — the core logic. Stdlib only (`urllib`), no packages.
  Reads public BSC/Ethereum/Base RPCs with fallback, and the Sourcify
  v2 API for verification status, ABI, and contract name.
- `api/screen.py` — the public HTTPS endpoint (Vercel serverless,
  Python `BaseHTTPRequestHandler`). `POST /api/screen`, `GET` returns
  usage info.
- `api/index.py` — root endpoint with agent info.

Run it locally:

```bash
python3 guard.py 0xA74081fd9bc9623A2d9321223C35b41016A7fd65
python3 guard.py 0xYourContract --wallet 0xYourWallet --spender 0xSpender
```

Or call the live endpoint:

```bash
curl -X POST https://jesshq-guard.vercel.app/api/screen \
  -H "Content-Type: application/json" \
  -d '{"contract":"0xA74081fd9bc9623A2d9321223C35b41016A7fd65"}'
```

## Build context

This agent grew out of real work: screening dozens of "free mint"
contracts for an AI agent wallet on BSC. The recurring failure mode was
always the same — a contract nobody had read, an approval nobody had
checked. The checks here are the ones that actually caught problems:
missing code (wrong address), unverified source (unreadable contract),
owner `withdraw`/`pause` (rug levers), and unlimited approvals left
behind after a mint.

Key decisions:

- **Deterministic scoring, not an LLM verdict.** The score comes from
  named checks with fixed deductions, so two runs on the same contract
  give the same answer and anyone can audit why.
- **Stdlib only.** No dependencies to install, no keys to leak, and
  the same file runs locally and on serverless.
- **Unverified caps at REVIEW.** A contract you cannot read should
  never be called SAFE, even if everything else looks fine.
- **zkVerify (optional):** the verdict itself is a checkable claim —
  "contract X scored N at time T from evidence E" — that a proof
  system like zkVerify could attest without revealing how the score
  was computed. That integration is future work; the agent is useful
  without it, and the track allows it.

## License

MIT. See [LICENSE](LICENSE).
