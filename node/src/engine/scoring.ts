/**
 * ATROSA SNR Scoring — Port of Python scoring logic
 */

import { GroundTruth, loadGroundTruth } from "./ingest.js";

export interface ScoreResult {
  score: number;
  flagged_tx_count: number;
  flagged_user_count: number;
  total_events: number;
  feedback: string;
  tx_recall?: number;
  user_recall?: number;
  tx_precision?: number;
  user_precision?: number;
  true_positive_txs?: string[];
  true_positive_users?: string[];
}

export function scoreDetections(
  flaggedTxIds: string[],
  flaggedUserIds: string[],
  totalEvents: number,
  groundTruth?: GroundTruth,
): ScoreResult {
  if (!groundTruth) {
    groundTruth = loadGroundTruth();
  }

  const gtTx = new Set(groundTruth.attacker_transaction_ids);
  const gtUsers = new Set(groundTruth.attacker_user_ids);
  const anomalyCount = groundTruth.anomaly_count;

  const result: ScoreResult = {
    score: 0,
    flagged_tx_count: flaggedTxIds.length,
    flagged_user_count: flaggedUserIds.length,
    total_events: totalEvents,
    feedback: "",
  };

  // --- Failure conditions ---
  if (flaggedTxIds.length === 0 && flaggedUserIds.length === 0) {
    result.feedback =
      "SCORE=0. No events flagged. Your detection logic did not identify any anomalies. " +
      "Revisit your hypothesis. Look for cross-source correlations: " +
      "transactions that appear in one log source but are missing expected counterparts in another.";
    return result;
  }

  const noiseThreshold = totalEvents * 0.01;
  if (flaggedTxIds.length > noiseThreshold) {
    result.feedback =
      `SCORE=0. Too noisy: flagged ${flaggedTxIds.length} transactions ` +
      `(>${Math.floor(noiseThreshold)} = 1% of ${totalEvents} total events). ` +
      "Your detection is too broad. Tighten your filters to isolate truly anomalous patterns.";
    return result;
  }

  // --- Scoring ---
  const flaggedTxSet = new Set(flaggedTxIds);
  const flaggedUserSet = new Set(flaggedUserIds);

  const truePosTx = [...flaggedTxSet].filter((id) => gtTx.has(id));
  const falsePosTx = [...flaggedTxSet].filter((id) => !gtTx.has(id));

  const truePosUsers = [...flaggedUserSet].filter((id) => gtUsers.has(id));
  const falsePosUsers = [...flaggedUserSet].filter((id) => !gtUsers.has(id));

  const txRecall = anomalyCount > 0 ? truePosTx.length / anomalyCount : 0;
  const userRecall = anomalyCount > 0 ? truePosUsers.length / anomalyCount : 0;

  const txPrecision = flaggedTxIds.length > 0 ? truePosTx.length / flaggedTxIds.length : 0;
  const userPrecision =
    flaggedUserIds.length > 0 ? truePosUsers.length / flaggedUserIds.length : 0;

  const recallScore = (txRecall * 0.6 + userRecall * 0.4) * 70;
  const precisionScore = (txPrecision * 0.6 + userPrecision * 0.4) * 30;

  const rawScore = recallScore + precisionScore;
  const score = Math.min(100, Math.max(0, Math.floor(rawScore)));

  // Build feedback
  const feedbackParts: string[] = [];
  feedbackParts.push(`SCORE=${score}.`);

  if (txRecall === 1.0 && userRecall === 1.0) {
    feedbackParts.push(`All ${anomalyCount} anomalies detected!`);
  } else {
    feedbackParts.push(
      `Detected ${truePosTx.length}/${anomalyCount} anomalous transactions, ` +
        `${truePosUsers.length}/${anomalyCount} anomalous users.`,
    );
  }

  if (falsePosTx.length > 0) {
    feedbackParts.push(`False positive transactions: ${falsePosTx.length}.`);
  }
  if (falsePosUsers.length > 0) {
    feedbackParts.push(`False positive users: ${falsePosUsers.length}.`);
  }

  if (score < 100) {
    if (txRecall < 1.0) {
      feedbackParts.push(
        "Hint: Look for transaction IDs that have a webhook CREDIT but no corresponding DEBIT. " +
          "Correlate across ledger_db_commits and payment_webhooks.",
      );
    }
    if (falsePosTx.length > 0) {
      feedbackParts.push(
        "Hint: Reduce false positives by requiring MULTIPLE correlated signals — " +
          "e.g., network_error on mobile + late webhook + missing debit.",
      );
    }
  }

  if (score === 100) {
    feedbackParts.push(
      "PERFECT DETECTION. Rule is ready for graduation to active_rules.json.",
    );
  }

  result.score = score;
  result.tx_recall = txRecall;
  result.user_recall = userRecall;
  result.tx_precision = txPrecision;
  result.user_precision = userPrecision;
  result.true_positive_txs = truePosTx;
  result.true_positive_users = truePosUsers;
  result.feedback = feedbackParts.join(" ");

  return result;
}
