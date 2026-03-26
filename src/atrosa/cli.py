"""
ATROSA CLI — Unified command-line interface
=============================================
Entry point for the `atrosa` command installed via pip.

Subcommands:
  atrosa hunt        Run the Hunter swarm orchestrator
  atrosa sentinel    Run the Sentinel live enforcement loop
  atrosa telemetry   Telemetry Engineer operations (audit, analyze, status, resolve)
  atrosa init        Generate synthetic telemetry data
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="atrosa",
        description="ATROSA — Autonomous Threat Response & Overwatch Swarm Agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands:
  hunt          Run the Hunter swarm to discover detection rules
  sentinel      Run the Sentinel to enforce graduated rules
  telemetry     Telemetry Engineer: audit, analyze, status, resolve
  init          Generate synthetic mock telemetry data

Examples:
  atrosa hunt --provider anthropic
  atrosa sentinel --dry-run
  atrosa telemetry audit
  atrosa init
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # --- hunt ---
    hunt_parser = subparsers.add_parser(
        "hunt",
        help="Run the Hunter swarm orchestrator",
        description="ATROSA Hunter Swarm Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Providers & default models:
  anthropic    claude-sonnet-4-20250514    (ANTHROPIC_API_KEY)
  openai       gpt-4o                      (OPENAI_API_KEY)
  gemini       gemini-2.5-flash            (GEMINI_API_KEY)
  openrouter   anthropic/claude-sonnet-4   (OPENROUTER_API_KEY)
  local        qwen2.5-coder:14b           (no key needed)
        """,
    )
    hunt_parser.add_argument(
        "--provider", "-p",
        choices=["anthropic", "openai", "gemini", "openrouter", "local"],
        default="anthropic",
        help="LLM provider to use (default: anthropic)",
    )
    hunt_parser.add_argument(
        "--model", "-m",
        default=None,
        help="Model name/ID (default: provider-specific)",
    )
    hunt_parser.add_argument(
        "--base-url",
        default=None,
        help="Custom API base URL (for local models: Ollama, LM Studio, vLLM)",
    )
    hunt_parser.add_argument(
        "--max-iterations", "-n",
        type=int,
        default=10,
        help="Max hunt iterations (default: 10)",
    )
    hunt_parser.add_argument(
        "--hunt-prompt",
        default="hunt.md",
        help="Path to hunt prompt file (default: hunt.md)",
    )
    hunt_parser.add_argument(
        "--tenant", "-t",
        default="default",
        help="Tenant ID for multi-customer deployment (default: default)",
    )
    hunt_parser.add_argument(
        "--production",
        action="store_true",
        help="Enable production mode (ground-truth-free scoring, temperature=0, audit trail)",
    )
    hunt_parser.add_argument(
        "--hunt-id",
        default=None,
        help="Hunt category ID from hunt_catalog (e.g. webhook_desync, sim_swap_ato)",
    )

    # --- sentinel ---
    sentinel_parser = subparsers.add_parser(
        "sentinel",
        help="Run the Sentinel live enforcement loop",
        description="ATROSA Sentinel Swarm — Live Threat Enforcement",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  simulate    Replay mock telemetry as a simulated live stream (default)
  watch       Tail a directory for new JSONL event files
        """,
    )
    sentinel_parser.add_argument(
        "--mode",
        choices=["simulate", "watch"],
        default="simulate",
        help="Stream mode (default: simulate)",
    )
    sentinel_parser.add_argument(
        "--interval", "-i",
        type=int,
        default=10,
        help="Seconds between batches (default: 10)",
    )
    sentinel_parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=500,
        help="Events per batch in simulate mode (default: 500)",
    )
    sentinel_parser.add_argument(
        "--watch-dir",
        default=None,
        help="Directory to watch for new JSONL files (watch mode only)",
    )
    sentinel_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Detect threats but don't execute mitigation actions",
    )

    # --- telemetry ---
    telemetry_parser = subparsers.add_parser(
        "telemetry",
        help="Telemetry Engineer operations",
        description="ATROSA Telemetry Engineer — Active Observability Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands:
  audit                  Audit current telemetry against ideal schema
  analyze                Analyze a specific Hunter error for data gaps
  status                 Show all observability requests
  resolve <REQ-ID>       Mark a request as resolved
        """,
    )
    tel_subparsers = telemetry_parser.add_subparsers(dest="telemetry_command", help="Telemetry subcommand")

    # telemetry audit
    tel_audit = tel_subparsers.add_parser("audit", help="Audit telemetry completeness")
    tel_audit.add_argument("--channel", action="append", default=None,
                           help="Delivery channel (repeatable: console, file, slack, github, jira)")

    # telemetry analyze
    tel_analyze = tel_subparsers.add_parser("analyze", help="Analyze a Hunter error")
    tel_analyze.add_argument("--error", "-e", default="", help="Error text")
    tel_analyze.add_argument("--hunt-log", default=None, help="Path to hunt iteration code")
    tel_analyze.add_argument("--error-log", default=None, help="Path to error log file")
    tel_analyze.add_argument("--channel", action="append", default=None,
                             help="Delivery channel (repeatable)")

    # telemetry status
    tel_subparsers.add_parser("status", help="Show request status")

    # telemetry resolve
    tel_resolve = tel_subparsers.add_parser("resolve", help="Resolve a request")
    tel_resolve.add_argument("request_id", help="Request ID to resolve (e.g. TEL-REQ-A1B2C3)")

    # --- init ---
    init_parser = subparsers.add_parser(
        "init",
        help="Generate synthetic mock telemetry data",
        description="Generate synthetic 24-hour fintech telemetry dataset with hidden anomalies",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate data even if it already exists",
    )

    # --- Parse and dispatch ---
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "hunt":
        from .orchestrator import run_hunt
        from pathlib import Path
        # Allow overriding the hunt prompt path
        import atrosa.orchestrator as orch_mod
        orch_mod.HUNT_PROMPT_PATH = Path(args.hunt_prompt)
        orch_mod.MAX_ITERATIONS = args.max_iterations
        success = run_hunt(
            provider_name=args.provider,
            model=args.model,
            base_url=args.base_url,
            tenant_id=getattr(args, "tenant", "default"),
            production=getattr(args, "production", False),
            hunt_id=getattr(args, "hunt_id", None),
        )
        sys.exit(0 if success else 1)

    elif args.command == "sentinel":
        from .sentinel import run_sentinel
        success = run_sentinel(
            mode=args.mode,
            interval=args.interval,
            batch_size=args.batch_size,
            watch_dir=args.watch_dir,
            dry_run=args.dry_run,
        )
        sys.exit(0 if success else 1)

    elif args.command == "telemetry":
        if args.telemetry_command is None:
            telemetry_parser.print_help()
            sys.exit(0)

        from .telemetry_engineer import cmd_audit, cmd_analyze, cmd_status, cmd_resolve

        if args.telemetry_command == "audit":
            channels = args.channel or ["console", "file"]
            cmd_audit(channels)

        elif args.telemetry_command == "analyze":
            channels = args.channel or ["console", "file"]
            cmd_analyze(
                error=args.error,
                hunt_log=args.hunt_log,
                error_log=args.error_log,
                channels=channels,
            )

        elif args.telemetry_command == "status":
            cmd_status()

        elif args.telemetry_command == "resolve":
            cmd_resolve(args.request_id)

    elif args.command == "init":
        from pathlib import Path
        if not args.force and Path("data/api_gateway.jsonl").exists():
            print("[*] Telemetry data already exists. Use --force to regenerate.")
            sys.exit(0)
        from .mock_telemetry import generate_all
        generate_all()

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
