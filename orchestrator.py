"""
ATROSA Orchestrator — Hunter Loop Controller
==============================================
Based on the Karpathy autoresearch pattern.

Drives the iterative loop:
1. Sends hunt.md + current state to the LLM
2. LLM rewrites detect.py
3. Executes detect.py in isolated subprocess
4. Scores the output via ingest.score_detections()
5. Feeds score + feedback back to LLM
6. Repeats until Score=100 or max iterations reached

On success (Score=100), graduates the rule to active_rules.json.

Usage:
    python orchestrator.py                                    # Default: Anthropic Claude Sonnet
    python orchestrator.py --provider openai                  # OpenAI GPT-4o
    python orchestrator.py --provider openai --model gpt-4.1  # OpenAI with specific model
    python orchestrator.py --provider gemini                  # Google Gemini
    python orchestrator.py --provider openrouter              # OpenRouter
    python orchestrator.py --provider local                   # Ollama (localhost:11434)
    python orchestrator.py --provider local --model llama3    # Ollama with specific model
    python orchestrator.py --provider local --base-url http://localhost:1234/v1  # LM Studio
"""

import argparse
import json
import subprocess
import sys
import os
import time
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from providers import create_provider, DEFAULT_MODELS, ENV_KEYS

# --- Config ---
MAX_ITERATIONS = 50   # Karpathy: unlimited. We cap at 50 for paid APIs, unlimited for local.
DETECT_TIMEOUT = 300  # seconds (Karpathy: 300s budget, 600s hard kill)
HUNT_PROMPT_PATH = Path("hunt.md")
DETECT_PATH = Path("detect.py")
RULES_PATH = Path("active_rules.json")
LOG_DIR = Path("logs")
RESULTS_TSV = Path("results.tsv")  # Cumulative experiment history (like Karpathy's results.tsv)

# Production scoring + audit (imported lazily to avoid circular deps)
_audit_trail = None
_production_scorer = None

# ===========================
# LLM INTERFACE
# ===========================
class HunterLLM:
    """Manages conversation with the Hunter LLM agent via any provider."""

    # Reset conversation every N iterations to prevent context saturation.
    # After reset, the LLM gets a self-contained context with schema + results
    # table + best code — no stale conversation history.
    RESET_EVERY = 5

    def __init__(self, provider_name: str = "anthropic", model: str = None, base_url: str = None):
        self.system_prompt = HUNT_PROMPT_PATH.read_text()
        self.provider = create_provider(
            provider_name=provider_name,
            system_prompt=self.system_prompt,
            model=model,
            base_url=base_url,
        )
        self._call_count = 0

    def reset(self):
        """Reset conversation history to prevent context saturation."""
        self.provider.reset()
        self._call_count = 0

    def get_detection_code(self, context: str) -> str:
        """Send context to LLM and get back a rewritten detect.py."""
        self._call_count += 1

        # Reset periodically to keep context lean (Karpathy: stdout > run.log)
        if self._call_count > 1 and self._call_count % self.RESET_EVERY == 1:
            self.reset()

        assistant_text = self.provider.chat(context)

        # Extract Python code from the response
        code = extract_code_block(assistant_text)
        if code is None:
            raise ValueError("LLM response did not contain a Python code block.")
        return code


def extract_code_block(text: str) -> Optional[str]:
    """Extract Python code from LLM output.

    Strategy (in order):
      1. Fenced code block (```python ... ```) — preferred
      2. AST-validated fallback — if the response (or a substring) parses as
         valid Python containing a detect() function, accept it. This handles
         models that don't consistently use fences (GLM, Gemini).
         Safe because code_validator.py runs AFTER extraction.
    """
    import re
    import ast

    # Strategy 1: Fenced code block
    pattern = r"```(?:python)?\s*\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Strategy 2: AST-validated fallback
    # Try the full text first, then try stripping non-code lines
    candidates = [text.strip()]

    # Also try extracting from first "import" or "def" to end
    for marker in ["import ", "def detect"]:
        idx = text.find(marker)
        if idx >= 0:
            candidates.append(text[idx:].strip())

    for candidate in candidates:
        try:
            tree = ast.parse(candidate)
            # Must contain a detect() function to be accepted
            has_detect = any(
                isinstance(node, ast.FunctionDef) and node.name == "detect"
                for node in ast.walk(tree)
            )
            if has_detect:
                return candidate
        except SyntaxError:
            continue

    return None


# ===========================
# SUBPROCESS EXECUTION
# ===========================
def run_detect() -> dict:
    """
    Execute detect.py in an isolated subprocess.
    Returns parsed JSON output or error dict.
    """
    try:
        result = subprocess.run(
            [sys.executable, "detect.py"],
            capture_output=True,
            text=True,
            timeout=DETECT_TIMEOUT,
            cwd=str(Path.cwd()),
        )

        stderr_output = result.stderr.strip()
        stdout_output = result.stdout.strip()

        if stderr_output:
            print(f"  [detect.py stderr] {stderr_output[:500]}", file=sys.stderr)

        if result.returncode != 0:
            return {
                "error": f"detect.py exited with code {result.returncode}",
                "stderr": stderr_output[:1000],
                "flagged_tx_ids": [],
                "flagged_user_ids": [],
            }

        # Parse the last line of stdout as JSON (detect.py may print debug to stderr)
        lines = stdout_output.strip().split("\n")
        json_line = lines[-1] if lines else ""
        return json.loads(json_line)

    except subprocess.TimeoutExpired:
        return {
            "error": f"detect.py timed out after {DETECT_TIMEOUT}s",
            "flagged_tx_ids": [],
            "flagged_user_ids": [],
        }
    except json.JSONDecodeError as e:
        return {
            "error": f"Failed to parse detect.py output as JSON: {e}",
            "raw_output": stdout_output[:500] if 'stdout_output' in dir() else "",
            "flagged_tx_ids": [],
            "flagged_user_ids": [],
        }


# ===========================
# RULE GRADUATION
# ===========================
def graduate_rule(detect_code: str, score_result: dict, iteration: int):
    """Save a proven detection rule to active_rules.json."""
    rule_id = f"FIN-RACE-{hashlib.sha256(detect_code.encode()).hexdigest()[:6].upper()}"
    rule_filename = f"rules/{rule_id.lower().replace('-', '_')}.py"

    # Save the detection script
    Path(rule_filename).write_text(detect_code)

    # Load or create rules file
    if RULES_PATH.exists():
        with open(RULES_PATH) as f:
            rules_data = json.load(f)
    else:
        rules_data = {"rules": []}

    # Compute code hash for integrity verification at load time
    code_hash = hashlib.sha256(detect_code.encode()).hexdigest()[:12]

    rule_entry = {
        "rule_id": rule_id,
        "threat_hypothesis": "Double-spend via webhook desync: CREDIT without matching DEBIT after forced network disconnect",
        "required_telemetry": ["api_gateway", "mobile_client_errors", "ledger_db_commits", "payment_webhooks"],
        "detection_logic_file": rule_filename,
        "mitigation_action": "suspend_user_id_and_flag_ledger",
        "confidence_score": score_result.get("tx_precision", 0.99),
        "graduated_at": datetime.now().isoformat(),
        "iterations_to_prove": iteration,
        "code_hash": code_hash,
    }

    rules_data["rules"].append(rule_entry)

    with open(RULES_PATH, "w") as f:
        json.dump(rules_data, f, indent=2)

    print(f"\n[+] RULE GRADUATED: {rule_id}")
    print(f"    Detection script: {rule_filename}")
    print(f"    Iterations: {iteration}")
    print(f"    Confidence: {rule_entry['confidence_score']}")

    return rule_id


# ===========================
# MAIN LOOP
# ===========================
def run_hunt(provider_name: str = "anthropic", model: str = None, base_url: str = None,
             tenant_id: str = "default", production: bool = False, hunt_id: str = None):
    """Main Hunter iteration loop."""
    global _audit_trail, _production_scorer

    print("=" * 60)
    print("  ATROSA — Hunter Swarm Orchestrator")
    print("=" * 60)

    # Ensure data exists
    if not Path("data/api_gateway.jsonl").exists():
        print("[!] No telemetry data found. Generating...")
        import mock_telemetry
        mock_telemetry.generate_all()

    # Load ground truth and total events for scoring
    import ingest
    harness = ingest.setup()
    ground_truth = harness["ground_truth"]
    total_events = harness["total_events"]

    # Initialize audit trail
    try:
        from audit import AuditTrail
        _audit_trail = AuditTrail(tenant_id=tenant_id)
        hunt_run_id = f"{hunt_id or 'hunt'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        _audit_trail.start_hunt(
            hunt_id=hunt_run_id,
            prompt_path=str(HUNT_PROMPT_PATH),
            provider=provider_name,
            model=model or DEFAULT_MODELS.get(provider_name, "default"),
            data_version=hashlib.sha256(str(total_events).encode()).hexdigest()[:8],
            schema_info="\n".join(schema_info) if 'schema_info' in dir() else "",
        )
        print(f"[*] Audit trail initialized: {hunt_run_id}")
    except Exception as e:
        print(f"[*] Audit trail unavailable: {e}")
        _audit_trail = None

    # Initialize production scorer if in production mode
    if production:
        try:
            from scoring import ProductionScorer
            _production_scorer = ProductionScorer(config={
                "max_flag_rate": 0.001,  # 0.1% — production threshold
                "graduation_threshold": 70,
            })
            print("[*] Production scoring enabled (no ground truth required)")
        except Exception as e:
            print(f"[!] Production scorer unavailable: {e}")
            _production_scorer = None

    # Initialize LLM
    display_model = model or DEFAULT_MODELS.get(provider_name, "default")
    print(f"\n[*] Initializing Hunter LLM agent...")
    print(f"    Provider: {provider_name}")
    print(f"    Model: {display_model}")
    print(f"    Mode: {'production' if production else 'development'}")
    if base_url:
        print(f"    Base URL: {base_url}")
    hunter = HunterLLM(provider_name=provider_name, model=model, base_url=base_url)

    # Read schema info for the initial prompt
    schema_info = []
    for name, df in [("df_api", harness["df_api"]), ("df_db", harness["df_db"]),
                     ("df_mobile", harness["df_mobile"]), ("df_webhooks", harness["df_webhooks"])]:
        schema_info.append(f"**{name}**: {len(df)} rows, columns: {list(df.columns)}")
        schema_info.append(f"  Sample row: {df.iloc[0].to_dict()}")

    detect_template = '''"""detect.py — ATROSA Hunter Detection Script"""
import json
import sys
import ingest

def detect():
    harness = ingest.setup()
    df_api = harness["df_api"]
    df_db = harness["df_db"]
    df_mobile = harness["df_mobile"]
    df_webhooks = harness["df_webhooks"]

    flagged_tx_ids = []
    flagged_user_ids = []

    # YOUR DETECTION LOGIC HERE

    return flagged_tx_ids, flagged_user_ids

if __name__ == "__main__":
    try:
        tx_ids, user_ids = detect()
        result = {
            "flagged_tx_ids": list(set(tx_ids)),
            "flagged_user_ids": list(set(user_ids)),
        }
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e), "flagged_tx_ids": [], "flagged_user_ids": []}))
        sys.exit(1)
'''

    initial_context = (
        "Begin your hunt. Here is the current dataset schema:\n\n"
        + "\n".join(schema_info)
        + f"\n\nTotal events across all sources: {total_events}"
        + "\n\nIMPORTANT: You MUST use exactly this template structure for detect.py. "
        + "Data is loaded via `ingest.setup()` — do NOT import data any other way.\n\n"
        + f"```python\n{detect_template}```\n\n"
        + "Fill in the detection logic. Return the COMPLETE detect.py file in a Python code block."
    )

    LOG_DIR.mkdir(exist_ok=True)
    Path("rules").mkdir(exist_ok=True)

    # --- Experiment History (like Karpathy's results.tsv) ---
    # Cumulative log of ALL iterations — the LLM sees full history each time
    experiment_history = []
    best_score = -1
    best_code = None
    best_iteration = 0

    # Initialize results.tsv
    results_path = LOG_DIR / "results.tsv"
    with open(results_path, "w") as f:
        f.write("iteration\tscore\tflagged_tx\tflagged_users\tstatus\tdescription\n")

    def _append_result(iteration, score, flagged_tx, flagged_users, status, description):
        with open(results_path, "a") as f:
            f.write(f"{iteration}\t{score}\t{flagged_tx}\t{flagged_users}\t{status}\t{description}\n")

    def _build_history_context():
        """Build cumulative experiment history for the LLM — like Karpathy's results.tsv."""
        if not experiment_history:
            return ""
        lines = ["\n## EXPERIMENT HISTORY (all prior attempts)"]
        lines.append("| Iter | Score | Flagged TX | Flagged Users | Status | Approach |")
        lines.append("|------|-------|-----------|--------------|--------|----------|")
        for exp in experiment_history:
            lines.append(
                f"| {exp['iteration']} | {exp['score']}/100 | {exp['flagged_tx']} | "
                f"{exp['flagged_users']} | {exp['status']} | {exp['description'][:60]} |"
            )
        if best_score > 0:
            lines.append(f"\n**BEST SO FAR: iteration {best_iteration}, score {best_score}/100**")
        return "\n".join(lines)

    def _build_feedback(iteration, score, score_result, flagged_tx, flagged_users, new_code):
        """Build rich feedback — tells the LLM exactly what worked and what didn't."""
        nonlocal best_score, best_code, best_iteration

        parts = [f"ITERATION {iteration} RESULT:"]
        parts.append(f"SNR Score: {score}/100")
        parts.append(f"Flagged {len(flagged_tx)} transactions, {len(set(flagged_users))} users.")

        # Precision and recall breakdown
        tp_tx = score_result.get("true_positive_txs", [])
        tp_users = score_result.get("true_positive_users", [])
        tx_recall = score_result.get("tx_recall", 0)
        user_recall = score_result.get("user_recall", 0)
        tx_precision = score_result.get("tx_precision", 0)
        user_precision = score_result.get("user_precision", 0)

        if len(flagged_tx) > 0:
            parts.append(f"Transaction precision: {tx_precision:.1%} ({len(tp_tx)} true positives / {len(flagged_tx)} flagged)")
            parts.append(f"Transaction recall: {tx_recall:.1%}")
        if len(flagged_users) > 0:
            parts.append(f"User precision: {user_precision:.1%} ({len(tp_users)} true positives / {len(set(flagged_users))} flagged)")
            parts.append(f"User recall: {user_recall:.1%}")

        parts.append(f"\n{score_result['feedback']}")

        # Compare to best
        if best_score > score and best_score > 0:
            parts.append(
                f"\nNOTE: Your best score was {best_score}/100 on iteration {best_iteration}. "
                f"This iteration scored lower. Consider building on what worked in iteration "
                f"{best_iteration} rather than trying a completely different approach."
            )
        elif score > best_score:
            parts.append(f"\nNEW BEST SCORE! Previous best was {best_score}/100. Keep refining this approach.")

        # Update best tracker
        if score > best_score:
            best_score = score
            best_code = new_code
            best_iteration = iteration

        # Include experiment history
        parts.append(_build_history_context())

        # After a conversation reset, include schema context so the message is self-contained
        # (the LLM has no memory of prior messages after reset)
        if (iteration % HunterLLM.RESET_EVERY) == 1 and iteration > 1:
            parts.append("\n## CONTEXT (conversation was reset to save memory)")
            parts.append("Dataset schema:\n" + "\n".join(schema_info))
            parts.append(f"Total events: {total_events}")
            parts.append(f"\nUse `harness = ingest.setup()` to load data. Template:")
            parts.append(f"```python\n{detect_template}```")

        # Karpathy-style encouragement when stuck
        if iteration > 5 and best_score < 20:
            parts.append(
                "\nYou've been iterating for a while with low scores. Think harder:\n"
                "- Re-examine the sample data for patterns you haven't tried\n"
                "- Try combining approaches from your best-scoring iterations\n"
                "- Try a radically different hypothesis about what makes fraud different\n"
                "- Focus on what the data ACTUALLY contains, not what you expect it to contain"
            )

        parts.append(
            "\nReturn the COMPLETE updated detect.py in a Python code block."
        )
        return "\n".join(parts)

    # --- Baseline Run (Karpathy: always establish reference first) ---
    print(f"\n{'─' * 40}")
    print(f"  BASELINE (establishing reference)")
    print(f"{'─' * 40}")

    baseline_code = detect_template
    DETECT_PATH.write_text(baseline_code)
    baseline_output = run_detect()
    if baseline_output.get("error"):
        print(f"[*] Baseline: no detection (empty template) — score 0")
        baseline_score = 0
    else:
        baseline_result = ingest.score_detections(
            flagged_tx_ids=baseline_output.get("flagged_tx_ids", []),
            flagged_user_ids=baseline_output.get("flagged_user_ids", []),
            total_events=total_events,
            ground_truth=ground_truth,
        )
        baseline_score = baseline_result.get("score", 0)
        print(f"[*] Baseline score: {baseline_score}/100")

    experiment_history.append({
        "iteration": 0, "score": baseline_score, "flagged_tx": 0,
        "flagged_users": 0, "status": "baseline", "description": "Empty template — no detection logic",
    })
    _append_result(0, baseline_score, 0, 0, "baseline", "Empty template")

    feedback_context = initial_context  # First iteration gets the initial context

    # --- Iteration Loop (Karpathy: LOOP FOREVER — we cap at MAX_ITERATIONS for cost) ---
    for iteration in range(1, MAX_ITERATIONS + 1):
        print(f"\n{'─' * 40}")
        print(f"  ITERATION {iteration}/{MAX_ITERATIONS}")
        print(f"{'─' * 40}")

        # Step 1: Get new detect.py from LLM
        print("[*] Requesting detection code from Hunter agent...")
        try:
            new_code = hunter.get_detection_code(initial_context if iteration == 1 else feedback_context)
        except Exception as e:
            print(f"[!] LLM error: {e}")
            experiment_history.append({
                "iteration": iteration, "score": 0, "flagged_tx": 0,
                "flagged_users": 0, "status": "llm_error", "description": str(e)[:60],
            })
            _append_result(iteration, 0, 0, 0, "llm_error", str(e)[:60])
            continue

        # Step 2: Validate code safety before writing
        try:
            from code_validator import validate_and_report
            if not validate_and_report(new_code):
                experiment_history.append({
                    "iteration": iteration, "score": 0, "flagged_tx": 0,
                    "flagged_users": 0, "status": "rejected", "description": "Security validation failed",
                })
                _append_result(iteration, 0, 0, 0, "rejected", "Security validation failed")
                feedback_context = (
                    f"ITERATION {iteration} RESULT:\n"
                    f"Your detect.py was REJECTED by the security validator. "
                    f"Detection scripts may only use: pandas, numpy, json, re, datetime, collections, math, sys. "
                    f"You MUST NOT use: os, subprocess, socket, urllib, eval, exec, open() for writing, "
                    f"or any network/file-system operations. "
                    f"\n{_build_history_context()}\n"
                    f"Return the COMPLETE corrected detect.py in a Python code block."
                )
                continue
        except ImportError:
            pass  # Validator not available — proceed without validation

        # Step 3: Write the new detect.py
        DETECT_PATH.write_text(new_code)
        print(f"[*] detect.py updated ({len(new_code)} chars)")

        # Log this iteration
        log_path = LOG_DIR / f"iteration_{iteration:02d}.py"
        log_path.write_text(new_code)

        # Step 4: Execute detect.py (300s timeout — Karpathy uses 5 min)
        print("[*] Executing detect.py...")
        t0 = time.time()
        detection_output = run_detect()
        elapsed = time.time() - t0
        print(f"[*] Execution completed in {elapsed:.2f}s")

        # Step 5: Check for errors
        if "error" in detection_output and detection_output["error"]:
            print(f"[!] Error: {detection_output['error']}")

            # Telemetry Engineer: analyze if this looks like a data gap
            error_text = detection_output["error"] + "\n" + detection_output.get("stderr", "")
            try:
                from telemetry_engineer import check_hunt_iteration
                tel_requests = check_hunt_iteration(
                    error_text=error_text,
                    detect_code=new_code,
                    channels=["console", "file"],
                    hunt_context=f"Hunt iteration {iteration}, prompt: {HUNT_PROMPT_PATH}",
                )
                if tel_requests:
                    print(f"[*] Telemetry Engineer created {len(tel_requests)} observability request(s)")
            except Exception:
                pass

            # Truncate stderr to avoid context pollution (Karpathy: stdout > run.log)
            stderr_snippet = detection_output.get("stderr", "")[:500]
            experiment_history.append({
                "iteration": iteration, "score": 0, "flagged_tx": 0,
                "flagged_users": 0, "status": "crashed",
                "description": detection_output["error"][:60],
            })
            _append_result(iteration, 0, 0, 0, "crashed", detection_output["error"][:60])

            feedback_context = (
                f"ITERATION {iteration} RESULT:\n"
                f"Your detect.py CRASHED with error:\n{detection_output['error']}\n"
            )
            if stderr_snippet:
                feedback_context += f"Stderr (truncated):\n{stderr_snippet}\n"
            feedback_context += (
                "\nFix the error and try again. Use `harness = ingest.setup()` to load data."
            )
            feedback_context += f"\n{_build_history_context()}"
            feedback_context += "\nReturn the COMPLETE corrected detect.py in a Python code block."
            continue

        # Step 6: Score the detection
        flagged_tx = detection_output.get("flagged_tx_ids", [])
        flagged_users = detection_output.get("flagged_user_ids", [])

        print(f"[*] Flagged: {len(flagged_tx)} transactions, {len(set(flagged_users))} users")

        # Use production scorer if available, otherwise use ground truth
        if _production_scorer and production:
            data = {
                "api": harness["df_api"], "db": harness["df_db"],
                "mobile": harness["df_mobile"], "webhooks": harness["df_webhooks"],
            }
            score_result = _production_scorer.score_for_autoresearch(
                flagged_tx_ids=flagged_tx, flagged_user_ids=flagged_users,
                total_events=total_events, data=data, ground_truth=None,
            )
        else:
            score_result = ingest.score_detections(
                flagged_tx_ids=flagged_tx,
                flagged_user_ids=flagged_users,
                total_events=total_events,
                ground_truth=ground_truth,
            )

        score = score_result["score"]
        print(f"[*] SNR Score: {score}/100")
        print(f"    {score_result['feedback']}")

        # Describe the approach (for history)
        approach_desc = f"Score {score}, flagged {len(flagged_tx)} tx / {len(set(flagged_users))} users"
        status = "kept" if score > best_score else "discarded"

        experiment_history.append({
            "iteration": iteration, "score": score,
            "flagged_tx": len(flagged_tx), "flagged_users": len(set(flagged_users)),
            "status": status, "description": approach_desc,
        })
        _append_result(iteration, score, len(flagged_tx), len(set(flagged_users)), status, approach_desc)

        # Log score
        score_log = {
            "iteration": iteration,
            "score": score,
            "flagged_tx": len(flagged_tx),
            "flagged_users": len(set(flagged_users)),
            "elapsed_s": elapsed,
            "feedback": score_result["feedback"],
            "best_score": max(best_score, score),
            "best_iteration": best_iteration if score <= best_score else iteration,
        }
        with open(LOG_DIR / f"score_{iteration:02d}.json", "w") as f:
            json.dump(score_log, f, indent=2)

        # Log to audit trail
        if _audit_trail:
            try:
                _audit_trail.log_iteration(
                    iteration=iteration, code=new_code, score=score,
                    feedback=score_result["feedback"],
                    execution_time_s=elapsed,
                    flagged_tx_count=len(flagged_tx),
                    flagged_user_count=len(set(flagged_users)),
                )
            except Exception:
                pass

        # Step 7: Check for graduation
        graduation_score = 100 if not production else score_result.get("graduation_threshold", 70)
        should_graduate = score >= graduation_score if production else score == 100
        if should_graduate:
            print(f"\n[!!!] {'PERFECT SCORE' if score == 100 else f'SCORE {score} >= {graduation_score}'} — GRADUATING RULE")
            rule_id = graduate_rule(new_code, score_result, iteration)
            if _audit_trail:
                try:
                    _audit_trail.graduate_rule(rule_id, new_code, score_result)
                except Exception:
                    pass
            print(f"\n[+] Hunt complete. Rule {rule_id} is now active.")
            print(f"    Total iterations: {iteration}")
            print(f"    Best score progression: {[e['score'] for e in experiment_history]}")
            return True

        # Step 8: Build rich feedback for next iteration (Karpathy: cumulative history + exact metrics)
        feedback_context = _build_feedback(
            iteration, score, score_result, flagged_tx, flagged_users, new_code
        )

        # Karpathy: if score regressed, revert to best code
        # (We don't revert detect.py — we tell the LLM about the regression in feedback)

    # End of loop — report final status
    print(f"\n[X] Max iterations ({MAX_ITERATIONS}) reached without graduation.")
    print(f"    Best score: {best_score}/100 on iteration {best_iteration}")
    print(f"    Score progression: {[e['score'] for e in experiment_history]}")

    # Save best code even if not graduated
    if best_code and best_score > 0:
        best_path = LOG_DIR / "best_detect.py"
        best_path.write_text(best_code)
        print(f"    Best detection saved to {best_path}")

    return False


def parse_args():
    parser = argparse.ArgumentParser(
        description="ATROSA Hunter Swarm Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Providers & default models:
  anthropic    claude-sonnet-4-20250514    (ANTHROPIC_API_KEY)
  openai       gpt-4o                      (OPENAI_API_KEY)
  gemini       gemini-2.5-flash            (GEMINI_API_KEY)
  openrouter   anthropic/claude-sonnet-4   (OPENROUTER_API_KEY)
  local        qwen2.5-coder:14b           (no key needed)

Examples:
  python orchestrator.py
  python orchestrator.py --provider openai --model gpt-4.1
  python orchestrator.py --provider local --model deepseek-coder-v2
  python orchestrator.py --provider local --base-url http://localhost:1234/v1
  python orchestrator.py --provider openrouter --model google/gemini-2.5-pro
        """,
    )
    parser.add_argument(
        "--provider", "-p",
        choices=["anthropic", "openai", "gemini", "openrouter", "local"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )
    parser.add_argument(
        "--model", "-m",
        default=None,
        help="Model name/ID (default: provider-specific, see below)",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="Custom API base URL (for local models: Ollama, LM Studio, vLLM)",
    )
    parser.add_argument(
        "--max-iterations", "-n",
        type=int,
        default=MAX_ITERATIONS,
        help=f"Max hunt iterations (default: {MAX_ITERATIONS}). Use 0 for unlimited (local models).",
    )
    parser.add_argument(
        "--hunt-prompt",
        default=str(HUNT_PROMPT_PATH),
        help=f"Path to hunt prompt file (default: {HUNT_PROMPT_PATH})",
    )
    parser.add_argument(
        "--tenant", "-t",
        default="default",
        help="Tenant ID for multi-customer deployment (default: default)",
    )
    parser.add_argument(
        "--production",
        action="store_true",
        help="Enable production mode (ground-truth-free scoring, temperature=0, audit trail)",
    )
    parser.add_argument(
        "--hunt-id",
        default=None,
        help="Hunt category ID from hunt_catalog (e.g. webhook_desync, sim_swap_ato)",
    )
    parser.add_argument(
        "--data-dir",
        default=None,
        help="Path to data directory (overrides default data/ for test runs)",
    )

    # --- Connector options ---
    parser.add_argument(
        "--source",
        choices=["csv", "stripe", "airweave"],
        default=None,
        help="Data source connector (csv, stripe, airweave). Pulls data before hunting.",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="API key for the data source (e.g. Stripe secret key)",
    )
    parser.add_argument(
        "--collection",
        default=None,
        help="Airweave collection ID (used with --source airweave)",
    )
    parser.add_argument(
        "--airweave-url",
        default=None,
        help="Airweave server URL (default: http://localhost:8080)",
    )
    return parser.parse_args()


def _run_connector(args) -> Optional[str]:
    """Run the specified connector and return the output data directory."""
    if not args.source:
        return None

    output_dir = Path(f"data/connector_{args.source}")

    if args.source == "csv":
        if not args.data_dir:
            print("[!] --data-dir is required with --source csv")
            sys.exit(1)
        from connectors.csv_import import CSVConnector
        connector = CSVConnector(data_dir=args.data_dir)

    elif args.source == "stripe":
        if not args.api_key:
            api_key = os.environ.get("STRIPE_API_KEY")
            if not api_key:
                print("[!] --api-key or STRIPE_API_KEY env var required with --source stripe")
                sys.exit(1)
        else:
            api_key = args.api_key
        from connectors.stripe import StripeConnector
        connector = StripeConnector(api_key=api_key)

    elif args.source == "airweave":
        from connectors.airweave_adapter import AirweaveAdapter
        connector = AirweaveAdapter(
            url=args.airweave_url,
            api_key=args.api_key,
            collection=args.collection,
        )
        if not connector.is_available():
            print(f"[!] Airweave not reachable at {connector.url}")
            print(f"    Start Airweave or use a different source (--source csv, --source stripe)")
            sys.exit(1)

    else:
        return None

    result = connector.run()
    result.save(str(output_dir))
    return str(output_dir.resolve())


if __name__ == "__main__":
    args = parse_args()
    HUNT_PROMPT_PATH = Path(args.hunt_prompt)

    # Handle unlimited iterations (--max-iterations 0)
    if args.max_iterations == 0:
        MAX_ITERATIONS = 999999  # Effectively unlimited (Karpathy: "LOOP FOREVER")
    else:
        MAX_ITERATIONS = args.max_iterations

    # Run connector if specified — pulls data before hunting
    connector_dir = _run_connector(args)
    data_dir = connector_dir or args.data_dir

    # Override data directory if specified (for testrun pipeline).
    # Set as env var so detect.py subprocess inherits it via ingest.DATA_DIR.
    if data_dir:
        os.environ["ATROSA_DATA_DIR"] = str(Path(data_dir).resolve())

    success = run_hunt(
        provider_name=args.provider,
        model=args.model,
        base_url=args.base_url,
        tenant_id=args.tenant,
        production=args.production,
        hunt_id=args.hunt_id,
    )
    sys.exit(0 if success else 1)
