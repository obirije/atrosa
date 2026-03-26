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
MAX_ITERATIONS = 10
DETECT_TIMEOUT = 30  # seconds
HUNT_PROMPT_PATH = Path("hunt.md")
DETECT_PATH = Path("detect.py")
RULES_PATH = Path("active_rules.json")
LOG_DIR = Path("logs")

# Production scoring + audit (imported lazily to avoid circular deps)
_audit_trail = None
_production_scorer = None

# ===========================
# LLM INTERFACE
# ===========================
class HunterLLM:
    """Manages conversation with the Hunter LLM agent via any provider."""

    def __init__(self, provider_name: str = "anthropic", model: str = None, base_url: str = None):
        self.system_prompt = HUNT_PROMPT_PATH.read_text()
        self.provider = create_provider(
            provider_name=provider_name,
            system_prompt=self.system_prompt,
            model=model,
            base_url=base_url,
        )

    def get_detection_code(self, context: str) -> str:
        """Send context to LLM and get back a rewritten detect.py."""
        assistant_text = self.provider.chat(context)

        # Extract Python code from the response
        code = extract_code_block(assistant_text)
        if code is None:
            raise ValueError("LLM response did not contain a Python code block.")
        return code


def extract_code_block(text: str) -> Optional[str]:
    """Extract the first Python code block from LLM output."""
    import re
    # Match ```python ... ``` or ``` ... ```
    pattern = r"```(?:python)?\s*\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no code block, check if the entire response looks like Python
    if "import " in text and "def detect" in text:
        return text.strip()
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

    rule_entry = {
        "rule_id": rule_id,
        "threat_hypothesis": "Double-spend via webhook desync: CREDIT without matching DEBIT after forced network disconnect",
        "required_telemetry": ["api_gateway", "mobile_client_errors", "ledger_db_commits", "payment_webhooks"],
        "detection_logic_file": rule_filename,
        "mitigation_action": "suspend_user_id_and_flag_ledger",
        "confidence_score": score_result.get("tx_precision", 0.99),
        "graduated_at": datetime.now().isoformat(),
        "iterations_to_prove": iteration,
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
    feedback_context = initial_context  # fallback if iteration 1 fails

    # --- Iteration Loop ---
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
            continue

        # Step 2: Write the new detect.py
        DETECT_PATH.write_text(new_code)
        print(f"[*] detect.py updated ({len(new_code)} chars)")

        # Log this iteration
        log_path = LOG_DIR / f"iteration_{iteration:02d}.py"
        log_path.write_text(new_code)

        # Step 3: Execute detect.py
        print("[*] Executing detect.py...")
        t0 = time.time()
        detection_output = run_detect()
        elapsed = time.time() - t0
        print(f"[*] Execution completed in {elapsed:.2f}s")

        # Step 4: Check for errors
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
                pass  # Telemetry Engineer is optional

            feedback_context = (
                f"ITERATION {iteration} RESULT:\n"
                f"Your detect.py CRASHED with error:\n{detection_output['error']}\n"
            )
            if "stderr" in detection_output:
                feedback_context += f"Stderr output:\n{detection_output['stderr'][:1000]}\n"
            feedback_context += (
                "\nFix the error and try again. REMEMBER: You MUST use `harness = ingest.setup()` to load data. "
                "Do NOT import data any other way. Return the COMPLETE corrected detect.py in a Python code block."
            )
            continue

        # Step 5: Score the detection
        flagged_tx = detection_output.get("flagged_tx_ids", [])
        flagged_users = detection_output.get("flagged_user_ids", [])

        print(f"[*] Flagged: {len(flagged_tx)} transactions, {len(flagged_users)} users")

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

        # Log score
        score_log = {
            "iteration": iteration,
            "score": score,
            "flagged_tx": len(flagged_tx),
            "flagged_users": len(flagged_users),
            "elapsed_s": elapsed,
            "feedback": score_result["feedback"],
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
                    flagged_user_count=len(flagged_users),
                )
            except Exception:
                pass

        # Step 6: Check for graduation
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
            return True

        # Step 7: Build feedback for next iteration
        feedback_context = (
            f"ITERATION {iteration} RESULT:\n"
            f"SNR Score: {score}/100\n"
            f"Flagged {len(flagged_tx)} transactions, {len(flagged_users)} users.\n"
            f"Feedback: {score_result['feedback']}\n"
        )
        if score_result.get("true_positive_txs"):
            feedback_context += f"Correctly identified TXs: {score_result['true_positive_txs']}\n"
        if score_result.get("true_positive_users"):
            feedback_context += f"Correctly identified users: {score_result['true_positive_users']}\n"
        feedback_context += (
            "\nImprove your detection logic based on this feedback. "
            "Return the COMPLETE updated detect.py in a Python code block."
        )

    print(f"\n[X] Max iterations ({MAX_ITERATIONS}) reached without perfect score.")
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
        help=f"Max hunt iterations (default: {MAX_ITERATIONS})",
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
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    HUNT_PROMPT_PATH = Path(args.hunt_prompt)
    success = run_hunt(
        provider_name=args.provider,
        model=args.model,
        base_url=args.base_url,
        tenant_id=args.tenant,
        production=args.production,
        hunt_id=args.hunt_id,
    )
    sys.exit(0 if success else 1)
