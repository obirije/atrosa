"""
ATROSA Production Scoring — Ground-Truth-Free Evaluation
==========================================================
The MVP scorer requires `.ground_truth.json` — known attacker IDs.
In production, there is no ground truth. This module provides multi-strategy
scoring that evaluates detection quality WITHOUT labeled data.

Strategies:
  1. Statistical Anomaly Scoring  — Does the rule flag rare, cross-source events?
  2. Proxy Signal Scoring         — Do flagged entities exhibit known fraud proxies?
  3. Retroactive Label Scoring    — Score against confirmed fraud (chargebacks, SARs)
  4. Peer Consistency Scoring     — Do multiple independent rules agree?

The combined score drives the autoresearch loop in production.

Usage:
    from scoring import ProductionScorer
    scorer = ProductionScorer(config)
    result = scorer.score(flagged_tx_ids, flagged_user_ids, data)
"""

import json
import math
from datetime import timedelta
from pathlib import Path
from typing import Optional

import pandas as pd


# ===========================
# STRATEGY: STATISTICAL ANOMALY
# ===========================
class StatisticalAnomalyStrategy:
    """
    Scores based on whether flagged events are statistically anomalous.

    A good rule flags RARE events that are unusual across multiple sources.
    A bad rule flags common events or events from only one source.

    Signals:
      - Flag rate (lower = better, but not zero)
      - Cross-source correlation depth (more sources = higher confidence)
      - Temporal clustering (anomalies cluster in time = more likely real)
      - Entity concentration (flags on few users = targeted, not noisy)
    """

    def __init__(self, max_flag_rate: float = 0.001, min_flag_rate: float = 0.00001):
        self.max_flag_rate = max_flag_rate  # 0.1% — above this is too noisy
        self.min_flag_rate = min_flag_rate  # 0.001% — below this is suspiciously quiet

    def score(self, flagged_tx_ids: list[str], flagged_user_ids: list[str],
              data: dict[str, pd.DataFrame]) -> dict:
        total_events = sum(len(df) for df in data.values())
        total_users = set()
        for df in data.values():
            if "user_id" in df.columns:
                total_users.update(df["user_id"].dropna().unique())

        n_flagged_tx = len(flagged_tx_ids)
        n_flagged_users = len(set(flagged_user_ids))
        n_total_users = len(total_users)

        result = {"strategy": "statistical_anomaly", "score": 0, "components": {}}

        # --- Flag rate scoring (0-25 points) ---
        if total_events == 0 or n_flagged_tx == 0:
            result["components"]["flag_rate"] = {"score": 0, "reason": "No flags or no events"}
            return result

        flag_rate = n_flagged_tx / total_events
        if flag_rate > self.max_flag_rate:
            fr_score = 0
            reason = f"Too noisy: {flag_rate:.4%} > {self.max_flag_rate:.4%} threshold"
        elif flag_rate < self.min_flag_rate:
            fr_score = 5  # Suspiciously low — might be too narrow
            reason = f"Very low flag rate: {flag_rate:.6%} — may be too narrow"
        else:
            # Score inversely proportional to flag rate (lower = better)
            log_range = math.log(self.max_flag_rate) - math.log(self.min_flag_rate)
            log_pos = math.log(self.max_flag_rate) - math.log(flag_rate)
            fr_score = int(25 * (log_pos / log_range))
            reason = f"Flag rate {flag_rate:.4%} within target range"

        result["components"]["flag_rate"] = {"score": fr_score, "rate": flag_rate, "reason": reason}

        # --- Cross-source depth (0-30 points) ---
        sources_with_flagged = 0
        for source_name, df in data.items():
            if "transaction_id" in df.columns:
                if df["transaction_id"].isin(flagged_tx_ids).any():
                    sources_with_flagged += 1
            elif "user_id" in df.columns:
                if df["user_id"].isin(flagged_user_ids).any():
                    sources_with_flagged += 1

        total_sources = len(data)
        if total_sources > 0:
            depth_ratio = sources_with_flagged / total_sources
            cs_score = int(30 * depth_ratio)
            reason = f"Flagged entities appear in {sources_with_flagged}/{total_sources} sources"
        else:
            cs_score = 0
            reason = "No data sources"

        result["components"]["cross_source_depth"] = {
            "score": cs_score, "sources_hit": sources_with_flagged,
            "total_sources": total_sources, "reason": reason,
        }

        # --- Entity concentration (0-20 points) ---
        if n_total_users > 0:
            user_flag_rate = n_flagged_users / n_total_users
            if user_flag_rate > 0.01:
                ec_score = 0
                reason = f"Flagging {user_flag_rate:.2%} of users — too broad"
            elif user_flag_rate > 0:
                ec_score = int(20 * min(1.0, (0.01 - user_flag_rate) / 0.01))
                reason = f"Flagging {n_flagged_users}/{n_total_users} users ({user_flag_rate:.4%})"
            else:
                ec_score = 0
                reason = "No users flagged"
        else:
            ec_score = 0
            reason = "No users in data"

        result["components"]["entity_concentration"] = {
            "score": ec_score, "flagged_users": n_flagged_users,
            "total_users": n_total_users, "reason": reason,
        }

        # --- Temporal clustering (0-25 points) ---
        tc_score = self._score_temporal_clustering(flagged_tx_ids, data)
        result["components"]["temporal_clustering"] = tc_score

        result["score"] = min(100, (
            fr_score + cs_score + ec_score + tc_score["score"]
        ))
        return result

    def _score_temporal_clustering(self, flagged_tx_ids: list[str],
                                   data: dict[str, pd.DataFrame]) -> dict:
        """Real anomalies tend to cluster in time. Random noise is uniformly distributed."""
        flagged_timestamps = []
        for df in data.values():
            if "transaction_id" in df.columns and "timestamp" in df.columns:
                mask = df["transaction_id"].isin(flagged_tx_ids)
                flagged_timestamps.extend(df.loc[mask, "timestamp"].tolist())

        if len(flagged_timestamps) < 2:
            return {"score": 10, "reason": "Too few flagged events for temporal analysis"}

        ts = sorted(pd.to_datetime(flagged_timestamps))
        gaps = [(ts[i+1] - ts[i]).total_seconds() for i in range(len(ts)-1)]
        avg_gap = sum(gaps) / len(gaps)

        # If flagged events were uniformly distributed across 24h window
        total_seconds = (ts[-1] - ts[0]).total_seconds() or 86400
        expected_uniform_gap = total_seconds / len(ts)

        # Clustering ratio: if avg_gap << expected_uniform_gap, events are clustered
        if expected_uniform_gap > 0:
            clustering_ratio = avg_gap / expected_uniform_gap
            if clustering_ratio < 0.3:
                score = 25  # Highly clustered
                reason = f"Strong temporal clustering (ratio={clustering_ratio:.2f})"
            elif clustering_ratio < 0.7:
                score = 15
                reason = f"Moderate temporal clustering (ratio={clustering_ratio:.2f})"
            else:
                score = 5
                reason = f"Weak temporal clustering (ratio={clustering_ratio:.2f}) — flags may be noise"
        else:
            score = 10
            reason = "Insufficient time range for clustering analysis"

        return {"score": score, "avg_gap_seconds": avg_gap, "reason": reason}


# ===========================
# STRATEGY: PROXY SIGNALS
# ===========================
class ProxySignalStrategy:
    """
    Scores based on whether flagged entities exhibit known fraud proxy signals.

    Even without ground truth, certain behaviors are strong fraud proxies:
      - High reversal/chargeback rates
      - Balance anomalies (credits without debits)
      - Velocity anomalies (unusual transaction frequency)
      - Network anomalies (many users from same IP/device)

    These proxies are configurable per tenant.
    """

    def __init__(self, proxy_checks: Optional[list[str]] = None):
        self.proxy_checks = proxy_checks or [
            "unmatched_credits",
            "reversal_rate",
            "velocity_anomaly",
            "balance_anomaly",
        ]

    def score(self, flagged_tx_ids: list[str], flagged_user_ids: list[str],
              data: dict[str, pd.DataFrame]) -> dict:
        result = {"strategy": "proxy_signals", "score": 0, "components": {}}
        if not flagged_tx_ids and not flagged_user_ids:
            return result

        scores = []

        if "unmatched_credits" in self.proxy_checks:
            s = self._check_unmatched_credits(flagged_tx_ids, data)
            result["components"]["unmatched_credits"] = s
            scores.append(s["score"])

        if "reversal_rate" in self.proxy_checks:
            s = self._check_reversal_rate(flagged_user_ids, data)
            result["components"]["reversal_rate"] = s
            scores.append(s["score"])

        if "velocity_anomaly" in self.proxy_checks:
            s = self._check_velocity_anomaly(flagged_user_ids, data)
            result["components"]["velocity_anomaly"] = s
            scores.append(s["score"])

        if "balance_anomaly" in self.proxy_checks:
            s = self._check_balance_anomaly(flagged_user_ids, data)
            result["components"]["balance_anomaly"] = s
            scores.append(s["score"])

        result["score"] = int(sum(scores) / len(scores)) if scores else 0
        return result

    def _check_unmatched_credits(self, flagged_tx_ids: list[str],
                                  data: dict[str, pd.DataFrame]) -> dict:
        """Flagged transactions should have more CREDITs without matching DEBITs than average."""
        df_db = data.get("db")
        if df_db is None or "operation" not in df_db.columns:
            return {"score": 0, "reason": "No ledger data available"}

        flagged_ops = df_db[df_db["transaction_id"].isin(flagged_tx_ids)]
        if flagged_ops.empty:
            return {"score": 0, "reason": "Flagged transactions not found in ledger"}

        has_credit = set(flagged_ops[flagged_ops["operation"] == "CREDIT"]["transaction_id"])
        has_debit = set(flagged_ops[flagged_ops["operation"] == "DEBIT"]["transaction_id"])
        unmatched = has_credit - has_debit

        if has_credit:
            unmatched_rate = len(unmatched) / len(has_credit)
            score = int(100 * unmatched_rate)
            reason = f"{len(unmatched)}/{len(has_credit)} flagged CREDITs have no matching DEBIT"
        else:
            score = 0
            reason = "No CREDITs in flagged transactions"

        return {"score": score, "unmatched_count": len(unmatched), "reason": reason}

    def _check_reversal_rate(self, flagged_user_ids: list[str],
                              data: dict[str, pd.DataFrame]) -> dict:
        """Flagged users should have higher reversal rates than the population."""
        df_db = data.get("db")
        if df_db is None or "operation" not in df_db.columns:
            return {"score": 0, "reason": "No ledger data available"}

        # Population reversal rate
        total_ops = len(df_db)
        total_reversals = len(df_db[df_db["operation"] == "REVERSAL"])
        pop_rate = total_reversals / total_ops if total_ops > 0 else 0

        # Flagged user reversal rate
        flagged_ops = df_db[df_db["user_id"].isin(flagged_user_ids)]
        flagged_total = len(flagged_ops)
        flagged_reversals = len(flagged_ops[flagged_ops["operation"] == "REVERSAL"])
        flagged_rate = flagged_reversals / flagged_total if flagged_total > 0 else 0

        if pop_rate > 0 and flagged_rate > pop_rate:
            lift = flagged_rate / pop_rate
            score = min(100, int(25 * lift))  # 4x lift = 100
            reason = f"Flagged users have {lift:.1f}x reversal rate vs population ({flagged_rate:.2%} vs {pop_rate:.2%})"
        elif flagged_rate == 0:
            score = 0
            reason = "No reversals among flagged users"
        else:
            score = 0
            reason = f"Flagged reversal rate ({flagged_rate:.2%}) not above population ({pop_rate:.2%})"

        return {"score": score, "flagged_rate": flagged_rate, "population_rate": pop_rate, "reason": reason}

    def _check_velocity_anomaly(self, flagged_user_ids: list[str],
                                 data: dict[str, pd.DataFrame]) -> dict:
        """Flagged users should have unusual transaction velocity."""
        df_api = data.get("api")
        if df_api is None or "user_id" not in df_api.columns:
            return {"score": 0, "reason": "No API data available"}

        # Population: median requests per user
        user_counts = df_api.groupby("user_id").size()
        pop_median = user_counts.median()
        pop_std = user_counts.std()

        # Flagged users
        flagged_counts = user_counts[user_counts.index.isin(flagged_user_ids)]
        if flagged_counts.empty:
            return {"score": 0, "reason": "Flagged users not found in API logs"}

        flagged_median = flagged_counts.median()

        if pop_std > 0:
            z_score = (flagged_median - pop_median) / pop_std
            score = min(100, max(0, int(abs(z_score) * 25)))
            direction = "higher" if z_score > 0 else "lower"
            reason = f"Flagged users have {direction} velocity (z={z_score:.1f}, median={flagged_median:.0f} vs {pop_median:.0f})"
        else:
            score = 0
            reason = "Insufficient variance in population velocity"

        return {"score": score, "z_score": float(z_score) if pop_std > 0 else 0, "reason": reason}

    def _check_balance_anomaly(self, flagged_user_ids: list[str],
                                data: dict[str, pd.DataFrame]) -> dict:
        """Flagged users should have balance anomalies (impossible states)."""
        df_db = data.get("db")
        if df_db is None or "balance_after" not in df_db.columns:
            return {"score": 0, "reason": "No balance data available"}

        flagged_ops = df_db[df_db["user_id"].isin(flagged_user_ids)]
        if flagged_ops.empty:
            return {"score": 0, "reason": "Flagged users not found in ledger"}

        # Check for balance inconsistencies
        anomalies = 0
        total = 0
        for _, row in flagged_ops.iterrows():
            total += 1
            if row["operation"] == "CREDIT":
                expected = row["balance_before"] + row["amount"]
            elif row["operation"] == "DEBIT":
                expected = row["balance_before"] - row["amount"]
            else:
                continue
            if abs(row["balance_after"] - expected) > 0.01:
                anomalies += 1

        if total > 0:
            anomaly_rate = anomalies / total
            score = min(100, int(anomaly_rate * 100))
            reason = f"{anomalies}/{total} ledger operations have balance inconsistencies"
        else:
            score = 0
            reason = "No operations to check"

        return {"score": score, "anomalies": anomalies, "total": total, "reason": reason}


# ===========================
# STRATEGY: RETROACTIVE LABELS
# ===========================
class RetroactiveLabelStrategy:
    """
    Scores rules against confirmed fraud labels that arrive after the fact.

    Sources of retroactive labels:
      - Chargebacks/reversals (arrive in days)
      - SAR filings (arrive in weeks)
      - Manual fraud analyst reviews (arrive in hours-days)
      - Law enforcement referrals (arrive in months)

    The scorer maintains a label store and re-evaluates rules as labels arrive.
    """

    def __init__(self, labels_path: Optional[Path] = None):
        self.labels_path = labels_path or Path("data/confirmed_fraud_labels.jsonl")
        self.labels = self._load_labels()

    def _load_labels(self) -> dict:
        """Load confirmed fraud labels. Format: {tx_id: {type, confirmed_at, source}}"""
        labels = {}
        if self.labels_path.exists():
            with open(self.labels_path) as f:
                for line in f:
                    entry = json.loads(line.strip())
                    labels[entry["transaction_id"]] = entry
        return labels

    def add_label(self, transaction_id: str, fraud_type: str, source: str):
        """Add a confirmed fraud label (called when chargebacks/SARs arrive)."""
        entry = {
            "transaction_id": transaction_id,
            "fraud_type": fraud_type,
            "source": source,
            "confirmed_at": pd.Timestamp.now().isoformat(),
        }
        self.labels[transaction_id] = entry
        with open(self.labels_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def score(self, flagged_tx_ids: list[str], flagged_user_ids: list[str],
              data: dict[str, pd.DataFrame]) -> dict:
        result = {"strategy": "retroactive_labels", "score": 0, "components": {}}

        if not self.labels:
            result["components"]["status"] = "No confirmed fraud labels available yet"
            result["score"] = -1  # Indicates "not scoreable" — should be excluded from average
            return result

        confirmed_fraud_txs = set(self.labels.keys())
        flagged_set = set(flagged_tx_ids)

        true_positives = flagged_set & confirmed_fraud_txs
        false_negatives = confirmed_fraud_txs - flagged_set
        false_positives = flagged_set - confirmed_fraud_txs

        # Note: false_positives here is an UPPER BOUND — some may be fraud not yet labeled
        precision = len(true_positives) / len(flagged_set) if flagged_set else 0
        recall = len(true_positives) / len(confirmed_fraud_txs) if confirmed_fraud_txs else 0

        if precision + recall > 0:
            f1 = 2 * (precision * recall) / (precision + recall)
        else:
            f1 = 0

        result["score"] = int(f1 * 100)
        result["components"] = {
            "true_positives": len(true_positives),
            "false_positives_upper_bound": len(false_positives),
            "false_negatives": len(false_negatives),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "total_labels": len(self.labels),
            "reason": f"F1={f1:.2f} against {len(self.labels)} confirmed labels (precision={precision:.2f}, recall={recall:.2f})",
        }
        return result


# ===========================
# STRATEGY: PEER CONSISTENCY
# ===========================
class PeerConsistencyStrategy:
    """
    Scores based on agreement between multiple independent rules.

    If 3 independent rules all flag the same user_id, that's much stronger
    signal than 1 rule flagging it. This strategy compares a rule's flags
    against other graduated rules' flags on the same data.
    """

    def __init__(self, rules_path: Optional[Path] = None):
        self.rules_path = rules_path or Path("active_rules.json")

    def score(self, flagged_tx_ids: list[str], flagged_user_ids: list[str],
              peer_flags: Optional[dict[str, set]] = None,
              data: dict[str, pd.DataFrame] = None) -> dict:
        """
        peer_flags: {rule_id: set(flagged_user_ids)} from other active rules.
        If not provided, returns neutral score.
        """
        result = {"strategy": "peer_consistency", "score": 0, "components": {}}

        if not peer_flags or len(peer_flags) < 2:
            result["score"] = -1  # Not enough peers to evaluate
            result["components"]["status"] = f"Need >= 2 peer rules, have {len(peer_flags or {})}"
            return result

        flagged_set = set(flagged_user_ids)
        agreements = {}

        for rule_id, peer_flagged in peer_flags.items():
            overlap = flagged_set & peer_flagged
            if flagged_set:
                agreement_rate = len(overlap) / len(flagged_set)
                agreements[rule_id] = {
                    "overlap_count": len(overlap),
                    "agreement_rate": agreement_rate,
                }

        if agreements:
            avg_agreement = sum(a["agreement_rate"] for a in agreements.values()) / len(agreements)
            result["score"] = int(avg_agreement * 100)
            result["components"] = {
                "peer_agreements": agreements,
                "avg_agreement_rate": avg_agreement,
                "reason": f"Average {avg_agreement:.0%} agreement with {len(agreements)} peer rules",
            }
        else:
            result["score"] = 0
            result["components"]["reason"] = "No peer flags to compare"

        return result


# ===========================
# COMBINED PRODUCTION SCORER
# ===========================
class ProductionScorer:
    """
    Combines all scoring strategies into a single production score.

    The combined score replaces the ground-truth scorer in the autoresearch loop.
    Strategies that return -1 (not scoreable) are excluded from the average.
    """

    def __init__(self, config: Optional[dict] = None):
        config = config or {}
        self.max_flag_rate = config.get("max_flag_rate", 0.001)
        self.min_flag_rate = config.get("min_flag_rate", 0.00001)
        self.labels_path = Path(config.get("labels_path", "data/confirmed_fraud_labels.jsonl"))
        self.rules_path = Path(config.get("rules_path", "active_rules.json"))
        self.graduation_threshold = config.get("graduation_threshold", 70)

        self.strategies = {
            "statistical": StatisticalAnomalyStrategy(
                max_flag_rate=self.max_flag_rate,
                min_flag_rate=self.min_flag_rate,
            ),
            "proxy": ProxySignalStrategy(),
            "retroactive": RetroactiveLabelStrategy(labels_path=self.labels_path),
            "peer": PeerConsistencyStrategy(rules_path=self.rules_path),
        }

        # Weights for combining strategies
        self.weights = config.get("weights", {
            "statistical": 0.30,
            "proxy": 0.35,
            "retroactive": 0.25,
            "peer": 0.10,
        })

    def score(self, flagged_tx_ids: list[str], flagged_user_ids: list[str],
              data: dict[str, pd.DataFrame],
              peer_flags: Optional[dict[str, set]] = None) -> dict:
        """
        Score a detection result using all available strategies.
        Returns a combined score (0-100) and per-strategy breakdowns.
        """
        results = {}

        # Run each strategy
        results["statistical"] = self.strategies["statistical"].score(
            flagged_tx_ids, flagged_user_ids, data
        )
        results["proxy"] = self.strategies["proxy"].score(
            flagged_tx_ids, flagged_user_ids, data
        )
        results["retroactive"] = self.strategies["retroactive"].score(
            flagged_tx_ids, flagged_user_ids, data
        )
        results["peer"] = self.strategies["peer"].score(
            flagged_tx_ids, flagged_user_ids, peer_flags=peer_flags, data=data
        )

        # Combine scores (exclude -1 strategies)
        weighted_sum = 0
        weight_sum = 0
        for strategy_name, result in results.items():
            if result["score"] >= 0:
                w = self.weights.get(strategy_name, 0.25)
                weighted_sum += result["score"] * w
                weight_sum += w

        combined_score = int(weighted_sum / weight_sum) if weight_sum > 0 else 0

        # Build feedback
        feedback_parts = [f"PRODUCTION_SCORE={combined_score}."]
        for name, result in results.items():
            if result["score"] >= 0:
                feedback_parts.append(f"{name}={result['score']}")

        should_graduate = combined_score >= self.graduation_threshold

        if should_graduate:
            feedback_parts.append(
                f"Score >= {self.graduation_threshold} threshold. Rule eligible for graduation."
            )
        else:
            # Find weakest strategy for improvement hints
            active = {k: v for k, v in results.items() if v["score"] >= 0}
            if active:
                weakest = min(active, key=lambda k: active[k]["score"])
                feedback_parts.append(
                    f"Weakest signal: {weakest} ({active[weakest]['score']}). "
                    f"Improve cross-source correlation and reduce flag rate."
                )

        return {
            "score": combined_score,
            "should_graduate": should_graduate,
            "strategies": results,
            "feedback": " ".join(feedback_parts),
            "flagged_tx_count": len(flagged_tx_ids),
            "flagged_user_count": len(set(flagged_user_ids)),
        }

    def score_for_autoresearch(self, flagged_tx_ids: list[str], flagged_user_ids: list[str],
                                total_events: int, data: dict[str, pd.DataFrame],
                                ground_truth: Optional[dict] = None) -> dict:
        """
        Drop-in replacement for ingest.score_detections().
        If ground_truth is provided (dev mode), uses it. Otherwise uses production scoring.
        """
        if ground_truth and ground_truth.get("attacker_transaction_ids"):
            # Dev mode — use ground truth scoring (existing behavior)
            from ingest import score_detections
            return score_detections(flagged_tx_ids, flagged_user_ids, total_events, ground_truth)

        # Production mode — use multi-strategy scoring
        return self.score(flagged_tx_ids, flagged_user_ids, data)
