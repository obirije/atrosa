# Sparkov Test Run Results

**Date:** 2026-03-27
**Dataset:** Sparkov (synthetic credit card, 1.3M transactions)
**Sample:** 50,000 rows (7,506 fraud / 762 users + 42,494 normal)
**Provider:** Anthropic Claude Sonnet 4
**Hunt prompt:** hunt_generic.md (no pattern hints)

## Result: Did Not Graduate (Best Score: 12/100)

| Iteration | Flagged Txns | Flagged Users | Score | Notes |
|---|---|---|---|---|
| 1 | timeout | - | 0 | Script too slow |
| 2 | 50,000 | 983 | 0 | Flagged everything (balance anomaly) |
| 3 | 50,000 | 983 | 0 | Same — all balances are 0.0 |
| 4 | 0 | 0 | 0 | Over-corrected |
| 5 | 100 | 91 | **9** | Found 56 real fraud users, 1 real fraud txn |
| 6 | 50 | 49 | **6** | Found 24 real fraud users |
| 7 | 0 | 0 | 0 | Over-tightened filters |
| 8 | 50,000 | 983 | 0 | Regressed |
| 9 | 80 | 80 | **7** | Found 43 real fraud users |
| 10 | 108 | 1 | **12** | Found 1 high-fraud user with 108 txns |

## What the Hunter Discovered

1. **Balance data unusable:** Sparkov has no balance columns — all `balance_before` and `balance_after` are 0.0 in the transform. The Hunter correctly identified this: "Transactions with both balances = 0: 50000" and tried to flag all as anomalous.

2. **Merchant name artifact:** All Sparkov merchants are named `fraud_*` (e.g., `fraud_Rutherford-Mertz`). This is Sparkov's naming convention, not a fraud indicator. The Hunter saw "Providers with 'fraud': 50000" and was confused.

3. **Amount-based detection worked partially:** In iteration 5, the Hunter found 100 extreme-amount outliers. 1 was a real fraud transaction and 56 were real fraud users — showing amount is a real signal in Sparkov.

4. **User-centric approach best:** Iteration 10 focused on a single user with 108 transactions — finding 1 real fraud user. This aligns with Sparkov's fraud pattern (repeat offender cards).

## Improvement Over PaySim

| Metric | PaySim | Sparkov |
|---|---|---|
| Best score | 2/100 | 12/100 |
| Real fraud users found | 0 | 56 |
| Iteration scoring > 0 | 1/10 | 4/10 |
| Score trend | Flat at 0 | Improving (0→9→6→7→12) |

The multi-dimensional data (geo, merchant, category) gave the Hunter more signal to work with, even though balances were missing.

## Dataset Limitations for ATROSA

1. **No balance data** — Sparkov is credit card transactions, not account ledger entries. No `balance_before`/`balance_after` signal.
2. **All merchants named `fraud_*`** — Confuses pattern detection; cannot use merchant name as a discriminator.
3. **No cross-source divergence** — Every transaction exists in all 4 sources identically. Real fraud creates asymmetries (failed webhooks, missing ledger entries, mobile errors) that don't exist here.

## Cost

~$0.15 (10 iterations, with rate limit retries adding ~5 min of wall time).

## Conclusion

Sparkov validated that the autoresearch loop can find partial signal in multi-dimensional data and improve across iterations. But 10 iterations is insufficient for convergence on this dataset — the fraud pattern (statistical amount/category/geo outliers) requires more exploration cycles than the webhook desync pattern the system was designed for.

Potential improvements:
- Increase max iterations to 20-30 for complex datasets
- Add richer feedback to the scorer (e.g., "you found N fraud users — your user detection is better than your transaction detection")
- Allow the Hunter to request data summaries between iterations (exploratory phase before detection phase)
