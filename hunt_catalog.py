"""
ATROSA Hunt Catalog — Threat Category Definitions
====================================================
Defines all 25 hunt categories across Tier 0-3. Each entry contains:
  - Threat hypothesis (what we're hunting for)
  - Required data sources (minimum DataFrames needed)
  - Detection signals (what the Hunter should look for)
  - hunt.md-compatible prompt (for the orchestrator)

The orchestrator uses this catalog to generate hunt prompts dynamically
based on the tenant's connected data sources.

Usage:
    from hunt_catalog import HuntCatalog
    catalog = HuntCatalog()
    prompt = catalog.get_hunt_prompt("webhook_desync", schema_info)
    available = catalog.get_available_hunts(["api", "db", "mobile", "webhooks"])
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HuntDefinition:
    """A single hunt category definition."""
    hunt_id: str
    name: str
    tier: str
    threat_hypothesis: str
    required_sources: list[str]
    enrichment_sources: list[str]  # Tier 1-3 sources that enhance detection
    detection_signals: list[str]
    mitigation_action: str
    prompt_template: str  # The hunt.md-compatible prompt
    severity: str = "high"  # critical, high, medium
    tags: list[str] = field(default_factory=list)


# ===========================
# TIER 0: UNIVERSAL
# ===========================
TIER_0_HUNTS = [
    HuntDefinition(
        hunt_id="webhook_desync",
        name="Webhook Desync / Double-Spend",
        tier="tier_0",
        threat_hypothesis="Double-spend via webhook desync: a payment webhook credits the destination account but no corresponding debit exists in the source account, caused by forced network disconnection during transfer.",
        required_sources=["api", "db", "webhooks"],
        enrichment_sources=["mobile"],
        detection_signals=[
            "Webhook status=success + ledger CREDIT exists but NO matching DEBIT for same transaction_id",
            "Mobile client shows network_error (E_NETWORK_LOST) on transfer screen within ±5min",
            "Webhook delivery_attempt > 1 AND latency_ms > 60000 (retried, late delivery)",
            "API POST /transfer/initiate precedes webhook by 90-300s (abnormal latency)",
        ],
        mitigation_action="suspend_user_id_and_flag_ledger",
        severity="critical",
        tags=["payments", "webhooks", "race-condition"],
        prompt_template="""# Hunt: Webhook Desync / Double-Spend

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find transactions where a payment webhook credited an account but the corresponding debit was never recorded. The attacker forces a network disconnect during transfer to create a race condition.

## Signature Pattern
1. A transaction_id exists in webhooks with status=success and a corresponding CREDIT in the ledger
2. That same transaction_id has NO matching DEBIT operation in the ledger
3. The user's mobile client shows a network_error with E_NETWORK_LOST on the transfer screen within seconds of the transfer initiation
4. The webhook arrived late (high latency_ms) and was retried (delivery_attempt > 1)

## Cross-Correlation Required
You MUST correlate across at least 2 data sources. Single-source detections will score 0.

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="toctou_race_condition",
        name="TOCTOU / Race Condition",
        tier="tier_0",
        threat_hypothesis="Time-of-check-time-of-use race condition: concurrent requests exploit the gap between balance check and balance mutation, allowing double-spend or duplicate payouts.",
        required_sources=["api", "db"],
        enrichment_sources=["mobile"],
        detection_signals=[
            "Multiple POST requests to /transfer/initiate or /transfer/confirm for the same user_id within <2s",
            "Multiple CREDITs where second balance_before == first balance_before (not yet updated)",
            "balance_after - balance_before != amount for DEBIT operations (integrity violation)",
            "Same session_id sending parallel requests with overlapping response_time_ms windows",
        ],
        mitigation_action="suspend_user_id_and_flag_ledger",
        severity="critical",
        tags=["payments", "race-condition", "concurrency"],
        prompt_template="""# Hunt: TOCTOU / Race Condition

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find users who submit concurrent transaction requests that exploit timing gaps between balance checks and balance updates.

## Signature Pattern
1. Multiple POST requests to transfer endpoints for the same user within a very short window (<2 seconds)
2. In the ledger, multiple CREDITs for the same user where the second CREDIT's balance_before equals the first CREDIT's balance_before (the balance wasn't updated between them)
3. Any DEBIT where balance_after - balance_before != -amount (balance integrity violation)

## Cross-Correlation Required
Correlate API request timing with ledger balance state transitions.

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="business_logic_flaw",
        name="Business Logic Flaw in Financial API",
        tier="tier_0",
        threat_hypothesis="Missing validation or broken state machine in payment APIs: skipped states, parameter tampering between API and ledger, insufficient funds bypass, or idempotency key replay with modified parameters.",
        required_sources=["api", "db"],
        enrichment_sources=["webhooks"],
        detection_signals=[
            "API request amount > ledger balance_after for that user (insufficient funds bypass)",
            "CREDIT amount in ledger != amount in webhook for same transaction_id (parameter tampering)",
            "status_code=200 on /transfer/confirm without preceding /transfer/initiate for same transaction_id (skipped state)",
            "Same idempotency_key producing different amounts (replay with modification)",
        ],
        mitigation_action="suspend_user_id_and_flag_ledger",
        severity="high",
        tags=["api", "validation", "state-machine"],
        prompt_template="""# Hunt: Business Logic Flaw

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find transactions that exploit missing validation, broken authorization, or state machine flaws in the payment API.

## Signature Pattern
1. Transfer initiated for amount greater than user's available balance
2. Amount discrepancy between API request, webhook callback, and ledger commit for the same transaction
3. Transfer confirmed without prior initiation (skipped state)
4. Same idempotency key used with different parameters

## Cross-Correlation Required
Compare API request parameters against ledger outcomes for the same transaction_id.

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="reversal_abuse",
        name="Refund / Reversal Abuse",
        tier="tier_0",
        threat_hypothesis="Systematic exploitation of refund and reversal processes: excessive reversal rates, automated reversals without dispute flow, or refund-then-re-spend patterns.",
        required_sources=["db"],
        enrichment_sources=["api", "webhooks"],
        detection_signals=[
            "REVERSAL count per user exceeding N within rolling 30-day window",
            "REVERSAL-to-DEBIT ratio per user > 15%",
            "payment.completed in webhooks followed by REVERSAL in ledger with no dispute API call between them",
            "Post-REVERSAL, same user initiates DEBIT of similar amount within hours",
        ],
        mitigation_action="flag_for_manual_review",
        severity="high",
        tags=["refunds", "chargebacks", "first-party-fraud"],
        prompt_template="""# Hunt: Refund / Reversal Abuse

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find users who systematically abuse the refund/reversal process. Look for patterns that indicate organized first-party fraud rather than legitimate disputes.

## Signature Pattern
1. Users with abnormally high REVERSAL counts in a rolling time window
2. Users whose REVERSAL-to-total-transaction ratio exceeds a threshold
3. REVERSALs that occur without any preceding dispute or status-check API call
4. Users who receive a REVERSAL then immediately initiate a new transaction of similar value

## Cross-Correlation Required
Correlate ledger REVERSALs with API request patterns and webhook payment confirmations.

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="velocity_anomaly",
        name="Velocity Anomaly (Auth Brute-Force / Enumeration)",
        tier="tier_0",
        threat_hypothesis="Automated credential stuffing, card testing, or enumeration attacks: abnormal request velocity to auth or payment endpoints, high failure rates from narrow IP ranges, or bot-like user agents.",
        required_sources=["api"],
        enrichment_sources=["webhooks"],
        detection_signals=[
            ">N failed auth requests (401/403) from same ip_address in rolling window",
            "Same ip_address hitting /auth/token with different user_ids in rapid succession",
            "High volume of micro-amount ($0.01-$1.00) requests to transfer endpoints",
            "Decline ratio per ip_address > 70% in 10-minute window",
            "Non-mobile user_agent (e.g. PostmanRuntime) at bot-like velocity on transfer endpoints",
        ],
        mitigation_action="rate_limit_and_block_ip",
        severity="high",
        tags=["bots", "credential-stuffing", "enumeration", "card-testing"],
        prompt_template="""# Hunt: Velocity Anomaly

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find IP addresses or sessions that exhibit automated attack patterns: credential stuffing, card number enumeration, or brute-force attempts.

## Signature Pattern
1. High volume of failed authentication attempts from a single IP or narrow range
2. Same IP attempting login with many different user_ids (credential rotation)
3. High volume of small-amount transactions (card testing pattern)
4. Unusually high decline/failure ratio from specific sources
5. Non-standard user agents operating at machine speed

## Cross-Correlation Required
Correlate API request patterns with webhook failure events.

{schema_section}

{constraints_section}""",
    ),
]

# ===========================
# TIER 1: COMMON ENRICHMENT
# ===========================
TIER_1_HUNTS = [
    HuntDefinition(
        hunt_id="sim_swap_ato",
        name="SIM Swap Account Takeover",
        tier="tier_1",
        threat_hypothesis="Account takeover via SIM swap: attacker hijacks victim's phone number, bypasses SMS-based 2FA, and immediately initiates high-value transfers from the compromised account.",
        required_sources=["api", "db"],
        enrichment_sources=["sim_intel", "device_intel", "mobile"],
        detection_signals=[
            "is_sim_swapped=true + new device_id + immediate /transfer/initiate",
            "Transfer amount >> user's historical average in ledger",
            "Login from new device immediately followed by sensitive action (no browsing)",
        ],
        mitigation_action="suspend_user_id_and_flag_ledger",
        severity="critical",
        tags=["ato", "sim-swap", "identity"],
        prompt_template="""# Hunt: SIM Swap Account Takeover

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find accounts where a SIM swap event correlates with unusual account activity — new device login followed immediately by high-value transfers.

## Key Enrichment Fields
Look for: is_sim_swapped, device_id, device_trust_score, line_type in the data.

## Signature Pattern
1. SIM swap indicator (is_sim_swapped=true or recent number port)
2. Login from a previously unseen device_id for this user
3. Immediate navigation to transfer/payment endpoints (skipping normal browsing)
4. Transfer amount significantly above user's historical pattern

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="device_farm_multi_accounting",
        name="Device Farm / Multi-Accounting",
        tier="tier_1",
        threat_hypothesis="Coordinated multi-accounting from device farms: same physical device or emulator creates multiple accounts to claim bonuses, referral rewards, or promotional credits, then aggregates and cashes out.",
        required_sources=["api", "db"],
        enrichment_sources=["device_intel", "email_risk"],
        detection_signals=[
            "Same device_id across N distinct user_ids",
            "Each user claims signup bonus (small CREDIT) followed by immediate full withdrawal (DEBIT)",
            "is_emulator=true or device_trust_score below threshold",
            "email_age_days < 7 and is_disposable=true across multiple accounts",
        ],
        mitigation_action="suspend_linked_accounts",
        severity="high",
        tags=["multi-accounting", "promo-abuse", "device-farm"],
        prompt_template="""# Hunt: Device Farm / Multi-Accounting

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find clusters of accounts that share device fingerprints or IP addresses and exhibit coordinated bonus-claiming behavior.

## Key Enrichment Fields
Look for: device_id, is_emulator, device_trust_score, email_age_days, is_disposable in the data.

## Signature Pattern
1. Multiple user_ids sharing the same device_id or ip_address + user_agent combination
2. Each account follows the same lifecycle: create → claim bonus → withdraw → go dormant
3. Accounts created from emulators or devices with low trust scores
4. Email addresses that are disposable or very recently created

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="impossible_travel_cashout",
        name="Impossible Travel + Cashout",
        tier="tier_1",
        threat_hypothesis="Account compromise indicated by geographically impossible login followed by immediate high-value withdrawal: user logs in from two distant locations within an impossibly short time window, then transfers funds.",
        required_sources=["api", "db"],
        enrichment_sources=["ip_risk"],
        detection_signals=[
            "geo_country shift > 500km within < 1 hour for same user_id",
            "is_vpn=false (not a VPN — genuine location change)",
            "High-value DEBIT in ledger immediately following the impossible travel event",
        ],
        mitigation_action="suspend_user_id_and_flag_ledger",
        severity="critical",
        tags=["ato", "impossible-travel", "geo-anomaly"],
        prompt_template="""# Hunt: Impossible Travel + Cashout

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find users whose login locations change impossibly fast, followed by financial activity.

## Key Enrichment Fields
Look for: ip_risk_score, is_vpn, is_proxy, geo_country, asn in the data.

## Signature Pattern
1. Same user_id with API requests from geographically distant locations within a short time window
2. The location change is NOT explained by VPN/proxy usage (is_vpn=false)
3. Financial transaction (transfer, withdrawal) occurs from the new location

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="synthetic_identity_onboarding",
        name="Synthetic Identity Onboarding",
        tier="tier_1",
        threat_hypothesis="Fabricated identity onboarding pipeline: account created with disposable email, VoIP phone number, and recently generated documents, followed by immediate high-value inbound transfer (onboarding-to-cashout).",
        required_sources=["api", "db"],
        enrichment_sources=["email_risk", "sim_intel"],
        detection_signals=[
            "email_age_days < 7 + is_disposable=true",
            "line_type=VoIP (not a real mobile number)",
            "KYC verification passes but onboarding-to-first-transaction time < 10 minutes",
            "First transaction is large inbound CREDIT from external source",
        ],
        mitigation_action="flag_for_enhanced_due_diligence",
        severity="high",
        tags=["synthetic-identity", "onboarding", "kyc"],
        prompt_template="""# Hunt: Synthetic Identity Onboarding

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find newly onboarded accounts that exhibit synthetic identity markers and rush to move money.

## Key Enrichment Fields
Look for: email_age_days, is_disposable, line_type, number_age_days in the data.

## Signature Pattern
1. Account created with very young or disposable email address
2. Phone number is VoIP type (not a physical SIM)
3. Unusually fast progression from KYC to first financial transaction
4. First transaction is a large inbound credit (funding the account for cashout)

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="proxy_credential_stuffing",
        name="Proxy-Masked Credential Stuffing",
        tier="tier_1",
        threat_hypothesis="Credential stuffing attack masked by proxy/VPN rotation: attacker tests stolen credentials through rotating proxies, achieves successful login, then immediately moves to cashout without normal browsing behavior.",
        required_sources=["api", "db"],
        enrichment_sources=["ip_risk"],
        detection_signals=[
            "is_proxy=true + >N failed auth from same ASN",
            "Eventual successful login + immediate /transfer/initiate (no browsing)",
            "Transfer to previously unseen beneficiary + large amount",
        ],
        mitigation_action="suspend_user_id_and_flag_ledger",
        severity="critical",
        tags=["ato", "credential-stuffing", "proxy"],
        prompt_template="""# Hunt: Proxy-Masked Credential Stuffing

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find successful logins that were preceded by proxy-masked credential testing, followed by immediate cashout.

## Key Enrichment Fields
Look for: is_proxy, is_vpn, ip_risk_score, asn in the data.

## Signature Pattern
1. Multiple failed auth attempts from proxy/VPN IPs within the same ASN
2. Eventually a successful login (possibly from a different proxy in same ASN)
3. Post-login behavior skips normal browsing — goes straight to transfer
4. Transfer is to a new beneficiary not in the user's history

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="emulator_promo_abuse",
        name="Emulator-Driven Promo Abuse",
        tier="tier_1",
        threat_hypothesis="Automated promo farming via emulators: scripted account creation on emulated devices, each claiming promotional credits, then funneling funds to a single collection account.",
        required_sources=["api", "db"],
        enrichment_sources=["device_intel"],
        detection_signals=[
            "is_emulator=true + N new user_ids from same device_id",
            "Each user: bonus CREDIT → immediate DEBIT of full amount",
            "Fan-in pattern: multiple users' DEBITs converge on same destination",
        ],
        mitigation_action="suspend_linked_accounts",
        severity="medium",
        tags=["promo-abuse", "emulator", "multi-accounting"],
        prompt_template="""# Hunt: Emulator-Driven Promo Abuse

## Threat Hypothesis
{threat_hypothesis}

## Your Target
Find clusters of accounts created on emulated devices that claim promotional credits and funnel them to a collection account.

## Key Enrichment Fields
Look for: device_id, is_emulator, is_rooted, device_trust_score in the data.

## Signature Pattern
1. Multiple accounts sharing the same device_id with is_emulator=true
2. Each account follows: signup → claim bonus → withdraw full amount
3. Withdrawals fan-in to a small number of destination accounts

{schema_section}

{constraints_section}""",
    ),
]

# ===========================
# TIER 2: IDENTITY & VERIFICATION
# ===========================
TIER_2_HUNTS = [
    HuntDefinition(
        hunt_id="kyc_gated_cashout",
        name="KYC-Gated Cashout Pipeline",
        tier="tier_2",
        threat_hypothesis="Fraudulent identity passes KYC but behavioral signals indicate automated or pre-staged document submission, followed by immediate high-value cashout before detection.",
        required_sources=["api", "db"],
        enrichment_sources=["kyc_idv"],
        detection_signals=[
            "liveness_score just above threshold + verification completed in <30s",
            "First transaction is large inbound CREDIT + immediate outbound DEBIT",
            "Onboarding-to-cashout time < 10 minutes",
        ],
        mitigation_action="flag_for_enhanced_due_diligence",
        severity="critical",
        tags=["kyc", "identity", "cashout"],
        prompt_template="""# Hunt: KYC-Gated Cashout Pipeline

## Threat Hypothesis
{threat_hypothesis}

## Key Enrichment Fields
Look for: verification_status, liveness_score, match_confidence, deepfake_detected in the data.

## Signature Pattern
1. KYC passes but with borderline scores (liveness just above threshold)
2. Unusually fast document submission (pre-staged synthetic documents)
3. First financial transaction occurs within minutes of KYC completion
4. First transaction is large and immediately followed by withdrawal

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="loan_stacking",
        name="Loan Stacking",
        tier="tier_2",
        threat_hypothesis="Simultaneous loan applications across multiple lenders within a 24-72 hour window, exploiting credit bureau update lag to obtain multiple disbursements before any lender sees the other obligations.",
        required_sources=["api", "db"],
        enrichment_sources=["credit_bureau", "device_intel"],
        detection_signals=[
            "Credit bureau inquiry_count spike within rolling 72-hour window",
            "Multiple /loan/apply API calls from same device_id within 72 hours",
            "Disbursements to same bank account from different providers in ledger",
        ],
        mitigation_action="flag_for_manual_review",
        severity="high",
        tags=["lending", "loan-stacking", "credit"],
        prompt_template="""# Hunt: Loan Stacking

## Threat Hypothesis
{threat_hypothesis}

## Key Enrichment Fields
Look for: inquiry_count, thin_file_flag, credit_age in the data.

## Signature Pattern
1. Spike in credit inquiry count from bureau data
2. Multiple loan application API calls from same device within short window
3. Loan disbursements arriving from different providers into the same account

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="bust_out_acceleration",
        name="Bust-Out Acceleration",
        tier="tier_2",
        threat_hypothesis="Synthetic identity builds credit history over months, then rapidly maxes out all credit lines and disappears. The bust-out is identifiable by a sudden behavioral inflection point.",
        required_sources=["api", "db"],
        enrichment_sources=["credit_bureau", "device_intel"],
        detection_signals=[
            "thin_file_flag=true + steady small transactions for months",
            "Sudden utilization spike: balance drops to near-zero after large DEBITs",
            "device_id change coinciding with behavioral inflection",
        ],
        mitigation_action="flag_for_manual_review",
        severity="high",
        tags=["credit", "synthetic-identity", "bust-out"],
        prompt_template="""# Hunt: Bust-Out Acceleration

## Threat Hypothesis
{threat_hypothesis}

## Key Enrichment Fields
Look for: thin_file_flag, credit_age, inquiry_count, device_id in the data.

## Signature Pattern
1. Account with thin credit file that has been building payment history
2. Sudden change in transaction behavior: large withdrawals, max utilization
3. Device or access pattern change coinciding with the behavioral shift

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="authorized_push_payment",
        name="Authorized Push Payment Scam",
        tier="tier_2",
        threat_hypothesis="Legitimate user is socially engineered into making a payment to a fraudster. The user exhibits cognitive stress signals during the transaction — hesitation, unusual navigation, coached behavior.",
        required_sources=["api", "db"],
        enrichment_sources=["behavioral_biometrics"],
        detection_signals=[
            "cognitive_stress_flag=true during transaction session",
            "Unusual navigation pattern (hesitation, repeated page visits)",
            "High-value transfer to a beneficiary with no prior interaction history",
        ],
        mitigation_action="flag_for_manual_review",
        severity="critical",
        tags=["social-engineering", "app-fraud", "behavioral"],
        prompt_template="""# Hunt: Authorized Push Payment Scam

## Threat Hypothesis
{threat_hypothesis}

## Key Enrichment Fields
Look for: session_risk_score, cognitive_stress_flag, typing_anomaly, is_remote_access in the data.

## Signature Pattern
1. Behavioral biometrics indicate cognitive stress or coached behavior
2. User navigates unusually (hesitation, back-and-forth between screens)
3. Transfer is to a never-before-seen beneficiary
4. Transfer amount is unusually high for this user's pattern

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="sanctions_evasion_layering",
        name="Sanctions Evasion via Layering",
        tier="tier_2",
        threat_hypothesis="Near-match on sanctions screening triggers a fuzzy alert. The entity then layers funds through splitting patterns across accounts that share device or network fingerprints.",
        required_sources=["api", "db"],
        enrichment_sources=["sanctions_pep", "device_intel"],
        detection_signals=[
            "screening_status=near_match (fuzzy match on sanctions list)",
            "Fan-out DEBIT pattern: splitting large amounts across multiple recipients",
            "Recipients share device_id or ip_address (connected network)",
        ],
        mitigation_action="escalate_to_compliance",
        severity="critical",
        tags=["sanctions", "aml", "layering"],
        prompt_template="""# Hunt: Sanctions Evasion via Layering

## Threat Hypothesis
{threat_hypothesis}

## Key Enrichment Fields
Look for: screening_status, match_type, watchlist_name, risk_level in the data.

## Signature Pattern
1. Sanctions screening returns a fuzzy/near match
2. The entity splits funds across multiple recipients (layering)
3. Recipients share device fingerprints, IP addresses, or other network indicators

{schema_section}

{constraints_section}""",
    ),
    HuntDefinition(
        hunt_id="deepfake_fast_cashout",
        name="Deepfake Document + Fast Cashout",
        tier="tier_2",
        threat_hypothesis="AI-generated identity document passes KYC verification but with borderline liveness scores. Combined with a very young email address and immediate cashout behavior, this indicates a synthetic onboarding attack.",
        required_sources=["api", "db"],
        enrichment_sources=["kyc_idv", "email_risk"],
        detection_signals=[
            "deepfake_detected=false BUT liveness_score is borderline",
            "email_age_days < 1",
            "First transaction within 10 minutes of KYC completion + large amount",
        ],
        mitigation_action="flag_for_enhanced_due_diligence",
        severity="critical",
        tags=["deepfake", "kyc", "synthetic-identity"],
        prompt_template="""# Hunt: Deepfake Document + Fast Cashout

## Threat Hypothesis
{threat_hypothesis}

## Key Enrichment Fields
Look for: liveness_score, deepfake_detected, match_confidence, email_age_days in the data.

## Signature Pattern
1. KYC passes but liveness/confidence scores are borderline (just above threshold)
2. Email address is extremely new (< 24 hours old)
3. Financial activity begins within minutes of KYC completion
4. First transaction is high value

{schema_section}

{constraints_section}""",
    ),
]

# ===========================
# TIER 3: SECTOR-SPECIFIC
# ===========================
TIER_3_HUNTS = [
    HuntDefinition(
        hunt_id="crypto_mixer_layering", name="Crypto Mixer Layering", tier="tier_3",
        threat_hypothesis="Funds from high-risk wallets (mixer exposure) flow through multiple on-chain hops, then convert to fiat via rapid withdrawal from a newly registered device.",
        required_sources=["api", "db"], enrichment_sources=["blockchain_analytics", "device_intel"],
        detection_signals=["wallet_risk_score=high + mixer_exposure", "Fan-in CREDITs from multiple wallets", "Rapid fiat conversion via /withdraw + new device_id"],
        mitigation_action="suspend_user_id_and_flag_ledger", severity="critical", tags=["crypto", "aml", "mixer"],
        prompt_template="# Hunt: Crypto Mixer Layering\n\n## Threat Hypothesis\n{threat_hypothesis}\n\nLook for wallet_risk_score, mixer_exposure, sanctioned_entity_flag, cluster_id.\nFind high-risk wallet inflows that rapidly convert to fiat via new devices.\n\n{schema_section}\n\n{constraints_section}",
    ),
    HuntDefinition(
        hunt_id="ghost_broking", name="Ghost Broking", tier="tier_3",
        threat_hypothesis="Unlicensed broker sells policies that are purchased then cancelled within days. Same device originates policies for unrelated customers at below-market premiums.",
        required_sources=["api", "db"], enrichment_sources=["insurance_claims", "device_intel"],
        detection_signals=["Policy purchased + cancelled within <14 days", "Same device_id across unrelated policyholders", "Premium << actuarial expectation"],
        mitigation_action="flag_for_manual_review", severity="high", tags=["insurance", "ghost-broking"],
        prompt_template="# Hunt: Ghost Broking\n\n## Threat Hypothesis\n{threat_hypothesis}\n\nLook for prior_claims_count, claim_type, siu_referral_flag, policy lifecycle events.\nFind policies with rapid purchase-cancel cycles from shared devices.\n\n{schema_section}\n\n{constraints_section}",
    ),
    HuntDefinition(
        hunt_id="claims_farming", name="Claims Farming", tier="tier_3",
        threat_hypothesis="Organized claims fraud: high prior claims count from shared database, claims filed shortly after policy inception, no genuine distress signals in behavioral data.",
        required_sources=["api", "db"], enrichment_sources=["insurance_claims", "behavioral_biometrics"],
        detection_signals=["prior_claims_count > threshold from ClaimSearch", "Claim filed within days of policy start", "cognitive_stress_flag=false"],
        mitigation_action="escalate_to_siu", severity="high", tags=["insurance", "claims-fraud"],
        prompt_template="# Hunt: Claims Farming\n\n## Threat Hypothesis\n{threat_hypothesis}\n\nLook for prior_claims_count, siu_referral_flag, cognitive_stress_flag.\nFind claims with high prior history, filed quickly, with no distress signals.\n\n{schema_section}\n\n{constraints_section}",
    ),
    HuntDefinition(
        hunt_id="bin_enumeration_escalation", name="BIN Enumeration Escalation", tier="tier_3",
        threat_hypothesis="Card network flags a BIN enumeration attack. The attacker finds a valid card, then immediately uses it for a high-value purchase.",
        required_sources=["api", "db"], enrichment_sources=["card_network_signals"],
        detection_signals=["BIN_attack_flag=true from card network", "High decline ratio in API gateway", "Successful auth → immediate high-value purchase"],
        mitigation_action="block_card_and_alert", severity="critical", tags=["payments", "card-testing", "enumeration"],
        prompt_template="# Hunt: BIN Enumeration Escalation\n\n## Threat Hypothesis\n{threat_hypothesis}\n\nLook for network_risk_score, bin_attack_flag, cross_merchant_velocity.\nFind enumeration attacks that succeed and immediately escalate to fraud.\n\n{schema_section}\n\n{constraints_section}",
    ),
    HuntDefinition(
        hunt_id="ach_kiting", name="ACH Kiting", tier="tier_3",
        threat_hypothesis="Cross-bank transfer cycling exploiting ACH settlement lag. Funds bounce between accounts, inflating balances before withdrawal. Returns accumulate R01 codes.",
        required_sources=["db"], enrichment_sources=["ach_returns"],
        detection_signals=["Cross-bank CREDIT→DEBIT cycling", "return_code accumulating R01s", "Transfers timed to weekends/holidays", "Balance returns to ~0 after each cycle"],
        mitigation_action="suspend_user_id_and_flag_ledger", severity="high", tags=["banking", "ach", "kiting"],
        prompt_template="# Hunt: ACH Kiting\n\n## Threat Hypothesis\n{threat_hypothesis}\n\nLook for return_code, return_rate, originator_risk.\nFind accounts with cyclic transfer patterns and accumulating ACH returns.\n\n{schema_section}\n\n{constraints_section}",
    ),
    HuntDefinition(
        hunt_id="cross_institution_fraud", name="Cross-Institution Fraud", tier="tier_3",
        threat_hypothesis="Entity flagged at another institution (consortium data) opens a new account here with matching device/IP fingerprint and immediately receives inbound transfers.",
        required_sources=["api", "db"], enrichment_sources=["consortium_flags", "device_intel"],
        detection_signals=["flagged_at_other_institution=true", "New account + device/IP matching flagged entity", "Immediate inbound transfer after account creation"],
        mitigation_action="flag_for_enhanced_due_diligence", severity="high", tags=["consortium", "cross-fi"],
        prompt_template="# Hunt: Cross-Institution Fraud\n\n## Threat Hypothesis\n{threat_hypothesis}\n\nLook for flagged_at_other_institution, fraud_type, date_flagged.\nFind accounts matching flagged entities that immediately receive funds.\n\n{schema_section}\n\n{constraints_section}",
    ),
    HuntDefinition(
        hunt_id="inr_chargeback_abuse", name="INR Chargeback Abuse", tier="tier_3",
        threat_hypothesis="Item-not-received claims filed despite delivery confirmation. Same user files multiple such claims, indicating organized refund abuse.",
        required_sources=["db", "api"], enrichment_sources=["shipping_delivery"],
        detection_signals=["delivery_confirmed=true + signature_obtained=true", "REVERSAL in ledger claiming 'not received'", "Same user has >N reversals in rolling window"],
        mitigation_action="flag_for_manual_review", severity="medium", tags=["ecommerce", "chargeback", "friendly-fraud"],
        prompt_template="# Hunt: INR Chargeback Abuse\n\n## Threat Hypothesis\n{threat_hypothesis}\n\nLook for delivery_confirmed, signature_obtained, delivery_address.\nFind reversals where delivery was confirmed but user claims non-receipt.\n\n{schema_section}\n\n{constraints_section}",
    ),
    HuntDefinition(
        hunt_id="income_fabrication", name="Income Fabrication (Lending)", tier="tier_3",
        threat_hypothesis="Loan applicant declares income significantly higher than verified income from open banking data. Combined with thin credit file and new email, indicates application fraud.",
        required_sources=["api", "db"], enrichment_sources=["open_banking", "email_risk", "credit_bureau"],
        detection_signals=["Declared income >> verified_income from open banking", "thin_file_flag=true", "email_age_days < 30"],
        mitigation_action="flag_for_manual_review", severity="high", tags=["lending", "application-fraud", "income"],
        prompt_template="# Hunt: Income Fabrication\n\n## Threat Hypothesis\n{threat_hypothesis}\n\nLook for verified_income, source_bank_balances, thin_file_flag, email_age_days.\nFind applications where declared income doesn't match banking reality.\n\n{schema_section}\n\n{constraints_section}",
    ),
]

# ===========================
# ALL HUNTS
# ===========================
ALL_HUNTS = TIER_0_HUNTS + TIER_1_HUNTS + TIER_2_HUNTS + TIER_3_HUNTS


# ===========================
# HUNT CATALOG
# ===========================
class HuntCatalog:
    """Registry of all hunt definitions. Generates prompts for the orchestrator."""

    def __init__(self):
        self._hunts = {h.hunt_id: h for h in ALL_HUNTS}

    def get(self, hunt_id: str) -> Optional[HuntDefinition]:
        return self._hunts.get(hunt_id)

    def list_all(self) -> list[HuntDefinition]:
        return ALL_HUNTS

    def list_by_tier(self, tier: str) -> list[HuntDefinition]:
        return [h for h in ALL_HUNTS if h.tier == tier]

    def get_available_hunts(self, connected_sources: list[str]) -> list[HuntDefinition]:
        """Return hunts whose required sources are all connected."""
        available = []
        for hunt in ALL_HUNTS:
            # Required sources must be present (Tier 0 base sources)
            base_sources = {"api", "db", "mobile", "webhooks"}
            required_met = all(
                s in connected_sources or s in base_sources
                for s in hunt.required_sources
            )
            # At least one enrichment source should be present for Tier 1+
            if hunt.tier == "tier_0":
                if required_met:
                    available.append(hunt)
            else:
                has_enrichment = any(s in connected_sources for s in hunt.enrichment_sources)
                if required_met and has_enrichment:
                    available.append(hunt)
        return available

    def get_hunt_prompt(self, hunt_id: str, schema_info: str,
                        max_iterations: int = 10) -> str:
        """Generate a complete hunt.md-compatible prompt for the orchestrator."""
        hunt = self._hunts.get(hunt_id)
        if not hunt:
            raise ValueError(f"Unknown hunt_id: {hunt_id}")

        constraints_section = f"""## Constraints

- Use only: pandas, json, re, datetime, collections (standard library + pandas).
- Do NOT modify ingest.py.
- Your detection must be **deterministic** — no randomness, no LLM calls.
- You MUST cross-correlate across at least 2 data sources.
- Flagging >0.1% of total traffic scores 0 (too noisy for production).
- Print debugging info to stderr. Print ONLY the final JSON result to stdout.
- You have up to {max_iterations} iterations to reach a passing score.

## Output Format

Print a JSON object to stdout:
```json
{{"flagged_tx_ids": ["TXN-..."], "flagged_user_ids": ["USR-..."]}}
```"""

        schema_section = f"## Available Data\n\n{schema_info}" if schema_info else ""

        prompt = hunt.prompt_template.format(
            threat_hypothesis=hunt.threat_hypothesis,
            schema_section=schema_section,
            constraints_section=constraints_section,
        )

        return prompt

    def summary(self) -> str:
        """Print a summary of all hunt categories."""
        lines = ["ATROSA Hunt Catalog", "=" * 50]
        for tier_name in ["tier_0", "tier_1", "tier_2", "tier_3"]:
            tier_def = {
                "tier_0": "Tier 0: Universal",
                "tier_1": "Tier 1: Common Enrichment",
                "tier_2": "Tier 2: Identity & Verification",
                "tier_3": "Tier 3: Sector-Specific",
            }
            lines.append(f"\n{tier_def[tier_name]}")
            lines.append("-" * 40)
            for hunt in self.list_by_tier(tier_name):
                lines.append(f"  [{hunt.severity.upper():8s}] {hunt.hunt_id:40s} {hunt.name}")
        lines.append(f"\nTotal: {len(ALL_HUNTS)} hunt categories")
        return "\n".join(lines)
