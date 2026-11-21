# ClaimCheck

**A scam-screening agent for crypto claim / airdrop announcements.**

Built for the [zkVerify Agent Games](https://agentgames.zkverify.io/) — Wildcard track.

## The problem

Every week, thousands of people lose funds to fake "claim" and "airdrop"
pages. The pattern is always similar: a convincing announcement page, a
countdown timer, and one fatal step — *"enter your seed phrase to verify"*,
*"send 0.05 ETH to receive 0.5 ETH"*, or a claim hosted on a lookalike
domain such as `metamask-claim-airdrop.example.com`. By the time a human
notices, the wallet is drained.

The people most exposed are exactly the people least equipped to check:
airdrop hunters working through dozens of announcements a day, often on a
phone, often under time pressure the scammers manufacture on purpose.

**ClaimCheck is a first-pass bodyguard for those announcements.** You give
it the URL (or the pasted text) of a claim announcement; it fetches the
page, pulls out the hard facts, screens the wording and the outbound links
against fraud heuristics, and hands back a structured, evidence-backed
report — *before* anyone connects a wallet.

## What it does

For every announcement, ClaimCheck produces a report containing:

- **Risk level** — `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` (the worst
  finding wins).
- **Findings with evidence** — each triggered rule includes the exact
  snippet of page text (or the offending link) that triggered it:
  - `secret_request` (**CRITICAL**) — the page asks for a seed phrase,
    recovery phrase, mnemonic, or private key. A negation guard ignores
    genuine safety copy such as *"we will never ask for your seed phrase"*.
  - `send_to_receive` (**HIGH**) — "send X … receive Y" schemes.
  - `deposit_to_claim` (**HIGH**) — a deposit, payment, or "activation
    fee" is demanded before claiming.
  - `guaranteed_returns` (**HIGH**) — guaranteed profit / "double your
    ETH" promises.
  - `lookalike_domain` (**HIGH**) — an outbound link whose host abuses a
    known brand (MetaMask, Uniswap, OpenSea, Phantom, Ledger, …) without
    being that brand's official domain.
  - `url_shortener` (**MEDIUM**) — claim links hidden behind bit.ly and
    similar shorteners.
  - `manufactured_urgency` (**LOW/MEDIUM**) — "act now", "only 17 spots
    left", "claim immediately", and friends.
- **Extracted facts** — EVM (`0x…`), Solana, and Bitcoin (bech32 + legacy)
  addresses, dates/deadlines, and all outbound links found on the page.
- **Evidence hash** — the SHA-256 of the exact bytes inspected, plus a
  report ID and UTC timestamp.

## Verifiability

A screening verdict is only useful if it can be checked. Every report
carries `evidence_sha256`: the hash of the precise content the agent
analysed. Anyone — a reviewer, a community moderator, the user themselves —
can re-fetch the same announcement, hash it, and confirm that the report
describes the same page, or catch that the page changed after the report
was issued. Reports are retrievable by ID from the same service
(`GET /report/<id>`), so a verdict can be shared as a link plus a hash.

**Honest note on zkVerify:** ClaimCheck does **not** currently integrate
zkVerify, and this README does not claim otherwise. The natural next step
is to anchor report hashes as zkVerify-verifiable claims — for example by
proving, via a zkTLS-style flow, that a given HTTPS response (the
announcement as served) hashes to the `evidence_sha256` in a report. That
would turn "trust this agent's screenshot" into "verify this claim
yourself", which is exactly the direction the Wildcard brief suggests.
The hash-first report format was chosen so that step can be added without
changing the API.

## How it works

```
POST /check {"url": "..."}            POST /check {"text": "..."}
        │                                      │
        ▼                                      │
 strict fetcher (urllib)                       │
 http/https only · no URL credentials          │
 redirects re-validated · 10 s timeout         │
 512 KB cap · errors → clean 502 JSON          │
        │                                      │
        └──────────────┬───────────────────────┘
                       ▼
        HTML → visible text + links (html.parser)
                       ▼
        fact extraction (addresses, dates, links)
                       ▼
        heuristic screening (rules above)
                       ▼
        report {id, timestamp, extracted, findings,
                risk_level, evidence_sha256}  →  stored in memory
```

Key decisions:

- **Pure Python 3 standard library.** No `pip install`, no supply chain to
  audit, nothing to break between a laptop and a free-tier host. The HTTP
  service is `http.server.ThreadingHTTPServer`; fetching is `urllib`.
- **Fail closed on fetching.** Only `http`/`https`, URLs with embedded
  credentials are rejected, redirects are re-validated (a redirect to a
  non-http scheme or a credentialed URL is refused), responses are capped
  at 512 KB with a 10-second timeout, and every fetch failure becomes a
  tidy JSON error — never a stack trace or a hung worker.
- **Evidence over opinions.** The agent never says "this is a scam". It
  says "this page contains this sentence, which matches this rule", and
  shows the sentence. Humans keep the final call.
- **The negation guard.** Legitimate projects warn users never to share
  their seed phrase. A naive keyword search flags the warning itself;
  ClaimCheck checks for a negation shortly before the term and lets
  genuine safety copy pass.

## HTTP API

| Endpoint | Description |
|---|---|
| `GET /` | Landing page with an explanation and a small web form — paste a URL, get a report in the browser. |
| `GET /health` | `{"status": "ok", ...}` liveness JSON. |
| `POST /check` | JSON body `{"url": "..."}` or `{"text": "..."}` → full report JSON. Invalid JSON → `400`; fetch failures → `502` with a plain-language `error`. |
| `GET /report/<id>` | A previously generated report (in-memory store). |
| `GET /demo` | Runs the agent against a built-in textbook-scam fixture and returns its report — the agent visibly working with zero input. |

### Example

```bash
curl -X POST https://<your-deployment>/check \
  -H 'Content-Type: application/json' \
  -d '{"text":"Send 0.05 ETH to the verification address and receive 0.5 ETH back."}'
```

```json
{
  "id": "…",
  "timestamp": "2026-11-21T04:29:51Z",
  "source": {"type": "text", "value": null},
  "extracted": {
    "evm_addresses": [],
    "solana_addresses": [],
    "btc_addresses": [],
    "dates": [],
    "links": []
  },
  "findings": [
    {
      "severity": "HIGH",
      "rule": "send_to_receive",
      "evidence": "Send 0.05 ETH to the verification address and receive 0.5 ETH back."
    }
  ],
  "risk_level": "HIGH",
  "evidence_sha256": "…",
  "content_bytes": 67
}
```

And `GET /demo` against the built-in scam fixture returns `CRITICAL` with
six findings: `secret_request`, `send_to_receive`, `guaranteed_returns`,
`lookalike_domain` (a `metamask-claim-airdrop.example.com` link),
`url_shortener` (a bit.ly link), and `manufactured_urgency` — plus the
fixture's EVM address and its "November 21, 2026" deadline extracted as
facts.

## Run it locally

Requires Python 3.10+ (developed on 3.12). Nothing to install.

```bash
python3 -m unittest -v     # 12 tests, all passing
python3 demo.py            # offline demo against local fixtures
python3 app.py             # serves on 0.0.0.0:$PORT (default 8000)
```

Then open <http://localhost:8000/>, or:

```bash
curl localhost:8000/health
curl localhost:8000/demo
curl -X POST localhost:8000/check -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/some-claim-page"}'
```

## Deploy (Render)

The repo ships a Render Blueprint (`render.yaml`): a free web service,
Python runtime, start command `python app.py`. Render injects `PORT`,
which the app reads. Connect the repo in Render → *New → Blueprint*, and
the service is live; no build step and no environment secrets are needed.

## Limitations (honest list)

- **Heuristics, not proof.** Rules are pattern-based. A novel scam wording
  can slip through (`LOW` means "nothing matched", not "safe"), and an
  unusually-worded legitimate page can be flagged. Findings always show
  their evidence so a human can overrule the agent.
- **Static fetch only.** The fetcher does not execute JavaScript, so
  claims rendered entirely client-side may be under-analysed. It also
  cannot see behind logins, CAPTCHAs, or geo-blocks; those fetches return
  a clean error instead of a report.
- **In-memory reports.** Reports live in a process-local dictionary and
  are lost on restart or redeploy. `GET /report/<id>` is a convenience,
  not an archive.
- **Address extraction is syntactic.** An extracted address is a string
  that *looks like* an address; ClaimCheck does not check balances,
  contract verification status, or on-chain history.
- **No zkVerify integration yet** — see the verifiability section above
  for the intended direction.

## Files

| File | Purpose |
|---|---|
| `app.py` | The whole agent: strict fetcher, extraction, screening rules, HTTP service. |
| `test_app.py` | `unittest` suite over local HTML fixtures (seed-phrase → CRITICAL, send-to-receive → HIGH, clean page → LOW, EVM/BTC/date/link extraction, URL validation, demo fixture). |
| `demo.py` | Offline demo: analyses the built-in scam fixture and a clean announcement, prints both reports. |
| `render.yaml` | Render Blueprint for one-click deployment. |
| `requirements.txt` | Intentionally empty of dependencies — standard library only. |

## License

MIT.
