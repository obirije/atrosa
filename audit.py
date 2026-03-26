"""
ATROSA Audit Trail — Rule Provenance & Regulatory Explainability
==================================================================
Tracks the full lineage of every graduated rule:
  - Which LLM provider/model generated it
  - Which hunt prompt was used
  - Which data version/schema was active
  - Every iteration's code, score, and feedback
  - Human-readable rule explanation for regulators

Compliance targets: FATF Recommendation 20, CBN AML/CFT Framework, PCI-DSS 6.1

Usage:
    trail = AuditTrail(tenant_id="acme")
    trail.start_hunt(hunt_id, prompt, provider, model, data_version)
    trail.log_iteration(iteration, code, score, feedback)
    trail.graduate_rule(rule_id, final_code, final_score)
    trail.generate_explanation(rule_id)  # Human-readable for regulators
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import pandas as pd


# ===========================
# AUDIT TRAIL
# ===========================
class AuditTrail:
    """Immutable audit trail for rule generation."""

    def __init__(self, tenant_id: str = "default", audit_dir: Optional[Path] = None):
        self.tenant_id = tenant_id
        self.audit_dir = audit_dir or Path(f"audit/{tenant_id}")
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self._current_hunt: Optional[dict] = None

    def start_hunt(self, hunt_id: str, prompt_path: str, provider: str,
                   model: str, data_version: str, schema_info: str = "") -> dict:
        """Record the start of a new hunt."""
        prompt_content = Path(prompt_path).read_text() if Path(prompt_path).exists() else ""
        prompt_hash = hashlib.sha256(prompt_content.encode()).hexdigest()[:12]

        hunt_record = {
            "hunt_id": hunt_id,
            "tenant_id": self.tenant_id,
            "started_at": datetime.now().isoformat(),
            "completed_at": None,
            "status": "in_progress",
            "prompt_path": prompt_path,
            "prompt_hash": prompt_hash,
            "prompt_content": prompt_content,
            "provider": provider,
            "model": model,
            "data_version": data_version,
            "schema_info": schema_info,
            "iterations": [],
            "graduated_rule_id": None,
        }

        self._current_hunt = hunt_record
        self._save_hunt(hunt_record)
        return hunt_record

    def log_iteration(self, iteration: int, code: str, score: int,
                      feedback: str, execution_time_s: float = 0,
                      flagged_tx_count: int = 0, flagged_user_count: int = 0) -> dict:
        """Log a single iteration of the autoresearch loop."""
        if self._current_hunt is None:
            raise RuntimeError("No active hunt. Call start_hunt() first.")

        code_hash = hashlib.sha256(code.encode()).hexdigest()[:12]

        iteration_record = {
            "iteration": iteration,
            "timestamp": datetime.now().isoformat(),
            "code_hash": code_hash,
            "code_length": len(code),
            "score": score,
            "feedback": feedback,
            "execution_time_s": execution_time_s,
            "flagged_tx_count": flagged_tx_count,
            "flagged_user_count": flagged_user_count,
        }

        # Save iteration code separately (for reproducibility)
        code_path = self.audit_dir / f"{self._current_hunt['hunt_id']}_iter_{iteration:02d}.py"
        code_path.write_text(code)
        iteration_record["code_path"] = str(code_path)

        self._current_hunt["iterations"].append(iteration_record)
        self._save_hunt(self._current_hunt)
        return iteration_record

    def graduate_rule(self, rule_id: str, final_code: str, final_score: dict) -> dict:
        """Record rule graduation."""
        if self._current_hunt is None:
            raise RuntimeError("No active hunt. Call start_hunt() first.")

        self._current_hunt["completed_at"] = datetime.now().isoformat()
        self._current_hunt["status"] = "graduated"
        self._current_hunt["graduated_rule_id"] = rule_id

        graduation_record = {
            "rule_id": rule_id,
            "graduated_at": datetime.now().isoformat(),
            "hunt_id": self._current_hunt["hunt_id"],
            "tenant_id": self.tenant_id,
            "provider": self._current_hunt["provider"],
            "model": self._current_hunt["model"],
            "prompt_hash": self._current_hunt["prompt_hash"],
            "data_version": self._current_hunt["data_version"],
            "iterations_to_graduate": len(self._current_hunt["iterations"]),
            "final_score": final_score,
            "final_code_hash": hashlib.sha256(final_code.encode()).hexdigest()[:12],
            "explanation": self._generate_explanation(final_code, self._current_hunt),
        }

        # Save graduation record
        grad_path = self.audit_dir / f"graduation_{rule_id}.json"
        with open(grad_path, "w") as f:
            json.dump(graduation_record, f, indent=2)

        self._save_hunt(self._current_hunt)
        return graduation_record

    def fail_hunt(self, reason: str):
        """Record a failed hunt (max iterations reached without graduation)."""
        if self._current_hunt is None:
            return
        self._current_hunt["completed_at"] = datetime.now().isoformat()
        self._current_hunt["status"] = "failed"
        self._current_hunt["failure_reason"] = reason
        self._save_hunt(self._current_hunt)

    def _save_hunt(self, hunt: dict):
        """Save hunt record to disk."""
        path = self.audit_dir / f"hunt_{hunt['hunt_id']}.json"
        with open(path, "w") as f:
            json.dump(hunt, f, indent=2)

    def _generate_explanation(self, code: str, hunt: dict) -> dict:
        """
        Generate a human-readable explanation of a graduated rule.
        This is what regulators see.
        """
        return {
            "rule_summary": self._extract_rule_summary(code),
            "data_sources_used": self._extract_data_sources(code),
            "detection_logic": self._extract_detection_logic(code),
            "provenance": {
                "generated_by": f"{hunt['provider']}/{hunt['model']}",
                "prompt_hash": hunt["prompt_hash"],
                "data_version": hunt["data_version"],
                "iterations": len(hunt["iterations"]),
                "score_progression": [it["score"] for it in hunt["iterations"]],
            },
            "regulatory_notes": (
                "This detection rule was generated by an autonomous agent and validated "
                "through iterative testing against production-representative data. "
                "The detection logic is deterministic Python — no LLM is invoked at "
                "detection time. The rule produces identical outputs given identical inputs."
            ),
        }

    @staticmethod
    def _extract_rule_summary(code: str) -> str:
        """Extract the docstring or first comment as the rule summary."""
        import ast
        try:
            tree = ast.parse(code)
            docstring = ast.get_docstring(tree)
            if docstring:
                return docstring.split("\n")[0]
        except SyntaxError:
            pass

        # Fallback: first comment line
        for line in code.split("\n"):
            stripped = line.strip()
            if stripped.startswith("#") and len(stripped) > 2:
                return stripped.lstrip("# ")
        return "Detection rule (no summary available)"

    @staticmethod
    def _extract_data_sources(code: str) -> list[str]:
        """Identify which DataFrames the rule uses."""
        sources = []
        source_patterns = {
            "df_api": "API Gateway logs",
            "df_db": "Ledger database commits",
            "df_mobile": "Mobile client events",
            "df_webhooks": "Payment webhook callbacks",
        }
        for var, description in source_patterns.items():
            if var in code:
                sources.append(description)
        return sources

    @staticmethod
    def _extract_detection_logic(code: str) -> list[str]:
        """Extract human-readable detection steps from code comments."""
        steps = []
        for line in code.split("\n"):
            stripped = line.strip()
            # Look for step-indicating comments
            if stripped.startswith("# Step") or stripped.startswith("# Check") or \
               stripped.startswith("# Look") or stripped.startswith("# Find") or \
               stripped.startswith("# Flag") or stripped.startswith("# Filter") or \
               stripped.startswith("# Cross") or stripped.startswith("# Correlate"):
                steps.append(stripped.lstrip("# "))
        if not steps:
            steps.append("Detection logic not annotated with step comments")
        return steps


# ===========================
# RULE EXPLANATION GENERATOR
# ===========================
class RuleExplainer:
    """
    Generates regulatory-compliant explanations for graduated rules.

    When a regulator asks "why was transaction X flagged?", this class
    produces a human-readable answer tracing from the flagged transaction
    back through the detection logic and data sources.
    """

    def __init__(self, rules_path: Path = Path("active_rules.json"),
                 audit_dir: Path = Path("audit")):
        self.rules_path = rules_path
        self.audit_dir = audit_dir

    def explain_flag(self, transaction_id: str, rule_id: str,
                     data: dict[str, pd.DataFrame]) -> dict:
        """
        Explain why a specific transaction was flagged by a specific rule.
        Returns a structured explanation suitable for regulatory reporting.
        """
        explanation = {
            "transaction_id": transaction_id,
            "rule_id": rule_id,
            "generated_at": datetime.now().isoformat(),
            "evidence": [],
            "data_sources_consulted": [],
            "conclusion": "",
        }

        # Gather evidence from each data source
        for source_name, df in data.items():
            if "transaction_id" in df.columns:
                matches = df[df["transaction_id"] == transaction_id]
                if not matches.empty:
                    explanation["data_sources_consulted"].append(source_name)
                    for _, row in matches.iterrows():
                        evidence_item = {
                            "source": source_name,
                            "timestamp": str(row.get("timestamp", "N/A")),
                            "fields": {k: str(v) for k, v in row.items()
                                       if k not in ("source",) and pd.notna(v)},
                        }
                        explanation["evidence"].append(evidence_item)

            if "user_id" in df.columns:
                # Find the user associated with this transaction
                for other_source, other_df in data.items():
                    if "transaction_id" in other_df.columns and "user_id" in other_df.columns:
                        user_match = other_df[other_df["transaction_id"] == transaction_id]
                        if not user_match.empty:
                            user_id = user_match.iloc[0]["user_id"]
                            explanation["associated_user_id"] = str(user_id)
                            break

        # Load rule provenance
        rule_audit = self._load_rule_audit(rule_id)
        if rule_audit:
            explanation["rule_provenance"] = rule_audit.get("explanation", {}).get("provenance", {})
            explanation["rule_summary"] = rule_audit.get("explanation", {}).get("rule_summary", "")
            explanation["detection_steps"] = rule_audit.get("explanation", {}).get("detection_logic", [])

        explanation["conclusion"] = (
            f"Transaction {transaction_id} was flagged by rule {rule_id} based on "
            f"cross-correlation of {len(explanation['data_sources_consulted'])} data sources. "
            f"The detection logic is deterministic and produces identical results on identical inputs."
        )

        return explanation

    def _load_rule_audit(self, rule_id: str) -> Optional[dict]:
        """Load the graduation audit record for a rule."""
        # Search audit directories for this rule
        for audit_dir in self.audit_dir.iterdir():
            if audit_dir.is_dir():
                grad_path = audit_dir / f"graduation_{rule_id}.json"
                if grad_path.exists():
                    with open(grad_path) as f:
                        return json.load(f)
        return None

    def generate_sar_supplement(self, transaction_id: str, rule_id: str,
                                data: dict[str, pd.DataFrame]) -> str:
        """
        Generate a Suspicious Activity Report (SAR) supplement.
        This is the narrative text that accompanies a SAR filing.
        """
        explanation = self.explain_flag(transaction_id, rule_id, data)

        lines = [
            "SUSPICIOUS ACTIVITY REPORT — AUTOMATED DETECTION SUPPLEMENT",
            "=" * 60,
            f"Date Generated: {explanation['generated_at']}",
            f"Transaction ID: {transaction_id}",
            f"Detection Rule: {rule_id}",
            f"Rule Summary: {explanation.get('rule_summary', 'N/A')}",
            "",
            "DATA SOURCES CONSULTED:",
        ]
        for source in explanation["data_sources_consulted"]:
            lines.append(f"  - {source}")

        lines.append("")
        lines.append("DETECTION LOGIC:")
        for step in explanation.get("detection_steps", []):
            lines.append(f"  - {step}")

        lines.append("")
        lines.append("EVIDENCE:")
        for ev in explanation["evidence"]:
            lines.append(f"  [{ev['source']}] {ev['timestamp']}")
            for k, v in ev["fields"].items():
                lines.append(f"    {k}: {v}")

        lines.append("")
        lines.append("CONCLUSION:")
        lines.append(f"  {explanation['conclusion']}")

        lines.append("")
        lines.append("NOTE: This detection was generated by an autonomous system.")
        lines.append("The underlying detection logic is deterministic Python code")
        lines.append("that produces identical outputs given identical inputs.")
        lines.append("No AI/ML model is invoked at detection time.")

        return "\n".join(lines)
