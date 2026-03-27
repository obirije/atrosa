# PaySim Test Run Results

**Date:** 2026-03-27
**Dataset:** PaySim (synthetic mobile money, 6.3M transactions)
**Sample:** 50,000 rows (8,213 fraud + 41,787 normal)
**Provider:** Anthropic Claude Sonnet 4
**Hunt prompt:** hunt_generic.md (no pattern hints)
**Runs:** 3 attempts across debugging iterations

## Result: Did Not Graduate

Best score: **2/100** (iteration 6, run 3) — found 25/8,213 fraud transactions.

## Why It Failed

PaySim's fraud signal is **single-dimensional** — it exists only in the ledger balances:
- Fraud: `balance_after = 0` AND `amount ≈ balance_before` (entire balance drained)
- The API, mobile, and webhook DataFrames have no distinguishing signal between fraud and normal transactions

ATROSA's cross-correlation architecture requires anomalous patterns across **at least 2 sources**. With only the ledger carrying signal, the Hunter couldn't satisfy this requirement.

## What the Hunter Discovered

Across 30 iterations (3 runs × 10 iterations):

1. **Iteration 1-2 (run 3):** Found 24,931 "balance inconsistencies" in the ledger — too many (50% of data). PaySim has many normal transactions where `balance_after ≠ balance_before - amount` due to the simulation model.
2. **Iteration 6 (run 3):** Scored 2/100 by flagging 500 extreme-amount transactions. 25 were real fraud (5% precision). Shows the Hunter can find partial signal but can't isolate it.
3. **Iteration 9 (run 3):** Found 7 more fraud transactions in 300 flagged (2.3% precision).

The Hunter oscillated between too noisy (flagging 20K+) and too selective (flagging 0-7). It could not converge because the single-source signal isn't strong enough to separate 8,213 fraud from 41,787 normal without cross-correlation from other sources.

## Infrastructure Bugs Found and Fixed

| Bug | Impact | Fix |
|---|---|---|
| Independent sampling per DataFrame | Transaction IDs didn't overlap across sources — cross-correlation impossible | Sample at transaction level before building DataFrames |
| `detect.py` subprocess didn't inherit `--data-dir` | Subprocess loaded project's `data/` instead of testrun data | Use `ATROSA_DATA_DIR` env var (inherited by subprocess) |
| Scorer hints hardcoded for webhook desync | Hunter misled toward wrong pattern on non-mock data | Made hints generic |
| Code validator blocked `pandas.rename()` | `rename` in blocklist caught legitimate DataFrame operations | Removed `rename` and `replace` from blocklist |
| Synthetic data injection in transform | Transform generated fake signals (random IPs, latencies, error codes) that didn't exist in raw data | Removed all synthetic generation — constants where data doesn't exist |

## Conclusion

PaySim is unsuitable for testing ATROSA's cross-correlation detection. It validates that:
- The pipeline works end-to-end (download → transform → ingest → hunt → score)
- The autoresearch loop iterates correctly with feedback
- Infrastructure bugs were found and fixed
- The code validator and security hardening work in practice

But it cannot validate detection quality because the dataset lacks multi-source fraud signals. A dataset with richer features (device fingerprints, identity data, behavioral signals) is needed.

## Cost

~$0.40 across 3 runs (30 iterations × ~4K input + ~2K output tokens per iteration, with rate limit retries).
