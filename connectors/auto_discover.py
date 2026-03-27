"""
Auto-Discovery + Mapping Wizard — Schema detection and interactive confirmation.

Two modes:
  1. Auto-discovery: heuristic column matching + type inference (no user input)
  2. Wizard: interactive CLI that shows sample data and asks user to confirm

Usage:
    # Auto-discover (non-interactive)
    from connectors.auto_discover import auto_discover_mapping
    mapping = auto_discover_mapping(raw_df)

    # Interactive wizard
    python -m connectors.auto_discover wizard --file transactions.csv
    python -m connectors.auto_discover discover --file transactions.csv
"""

import json
import sys
from pathlib import Path
from typing import Optional

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from schema_normalizer import SchemaNormalizer, CANONICAL_SCHEMA


# ===========================
# AUTO-DISCOVERY (non-interactive)
# ===========================
def auto_discover_mapping(df: pd.DataFrame, source: str = "api") -> dict:
    """
    Automatically discover column mappings from raw data.
    Returns a mapping config dict suitable for SchemaNormalizer.

    Uses three strategies:
      1. Exact name match against canonical schema
      2. Alias match (e.g., "customer_ref" → "user_id")
      3. Type inference (detect timestamps, amounts, IDs by content)
    """
    schema = CANONICAL_SCHEMA.get(source, {})
    mapping = {}
    used_columns = set()

    # Strategy 1 + 2: Name matching (handled by SchemaNormalizer.auto_discover)
    normalizer = SchemaNormalizer.auto_discover({source: df})
    mapping.update(normalizer.mappings.get(source, {}))
    used_columns.update(mapping.values())

    # Strategy 3: Type inference for unmapped required fields
    for field_group in ["required", "optional"]:
        for canonical_name, field_def in schema.get(field_group, {}).items():
            if canonical_name in df.columns or canonical_name in mapping:
                continue  # Already mapped

            target_type = field_def["type"]
            candidate = _infer_column(df, canonical_name, target_type, used_columns)
            if candidate:
                mapping[canonical_name] = candidate
                used_columns.add(candidate)

    return mapping


def _infer_column(df: pd.DataFrame, canonical_name: str, target_type: str,
                  used: set) -> Optional[str]:
    """Infer which raw column best matches a canonical field by examining content."""
    available = [c for c in df.columns if c not in used]
    if not available:
        return None

    if target_type == "datetime":
        for col in available:
            sample = df[col].dropna().head(10)
            if _looks_like_timestamp(sample):
                return col

    elif target_type == "float" and "amount" in canonical_name:
        for col in available:
            if df[col].dtype in ("float64", "int64"):
                vals = df[col].dropna()
                if len(vals) > 0 and vals.min() >= 0 and vals.max() < 1e10:
                    return col

    elif target_type == "str" and "user_id" in canonical_name:
        for col in available:
            if df[col].dtype == "object":
                nunique = df[col].nunique()
                # User IDs have moderate cardinality (not 1, not equal to row count)
                if 2 < nunique < len(df) * 0.9:
                    return col

    elif target_type == "str" and "transaction_id" in canonical_name:
        for col in available:
            if df[col].dtype == "object":
                nunique = df[col].nunique()
                # Transaction IDs are ~unique per row
                if nunique > len(df) * 0.8:
                    return col

    return None


def _looks_like_timestamp(sample: pd.Series) -> bool:
    """Check if a series looks like timestamp data."""
    try:
        pd.to_datetime(sample, format="mixed")
        return True
    except Exception:
        pass

    # Check if it's a unix timestamp (large integers)
    try:
        vals = sample.astype(float)
        if vals.min() > 1e9 and vals.max() < 2e10:  # 2001-2033 range
            return True
    except Exception:
        pass

    return False


# ===========================
# INTERACTIVE WIZARD
# ===========================
def run_wizard(df: pd.DataFrame, source: str = "api") -> dict:
    """
    Interactive CLI wizard that shows sample data and asks user to confirm mappings.
    Returns a confirmed mapping config.
    """
    print("=" * 60)
    print("  ATROSA — Schema Mapping Wizard")
    print("=" * 60)
    print(f"\n  Source: {source}")
    print(f"  Rows: {len(df):,}")
    print(f"  Columns: {len(df.columns)}")

    # Show sample data
    print(f"\n  Sample data (first 3 rows):")
    print(f"  {'─' * 50}")
    for col in df.columns[:15]:
        samples = df[col].dropna().head(3).tolist()
        dtype = str(df[col].dtype)
        print(f"    {col:30s} ({dtype:8s}) → {samples}")
    if len(df.columns) > 15:
        print(f"    ... +{len(df.columns) - 15} more columns")

    # Auto-discover first
    print(f"\n  Running auto-discovery...")
    auto_mapping = auto_discover_mapping(df, source)

    schema = CANONICAL_SCHEMA.get(source, {})
    confirmed = {}

    print(f"\n  Confirm or correct each mapping:")
    print(f"  (Press Enter to accept, type a column name to override, 's' to skip)")
    print(f"  {'─' * 50}")

    for field_group in ["required", "optional"]:
        for canonical_name, field_def in schema.get(field_group, {}).items():
            # Check auto-discovered mapping
            auto_match = auto_mapping.get(canonical_name)
            direct_match = canonical_name if canonical_name in df.columns else None
            suggestion = direct_match or auto_match

            required_tag = " [REQUIRED]" if field_group == "required" else ""
            if suggestion:
                prompt = f"    {canonical_name}{required_tag}\n      → auto-mapped to '{suggestion}'"
                prompt += f"\n      Accept? [Enter=yes, column name=override, s=skip]: "
            else:
                prompt = f"    {canonical_name}{required_tag}\n      → no auto-match found"
                prompt += f"\n      Enter column name or 's' to skip: "

            try:
                user_input = input(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print("\n  Wizard cancelled.")
                return confirmed

            if user_input == "":
                # Accept auto-mapping
                if suggestion and suggestion != canonical_name:
                    confirmed[canonical_name] = suggestion
            elif user_input.lower() == "s":
                continue  # Skip
            elif user_input in df.columns:
                confirmed[canonical_name] = user_input
            else:
                print(f"      [!] Column '{user_input}' not found. Skipping.")

    print(f"\n  {'─' * 50}")
    print(f"  Confirmed mappings: {len(confirmed)}")
    for canonical, raw_col in confirmed.items():
        print(f"    {raw_col} → {canonical}")

    return confirmed


def save_mapping(mapping: dict, output_path: str, source: str = "api"):
    """Save a mapping config to JSON file."""
    config = {
        "column_mappings": {source: mapping},
        "value_mappings": {},
    }
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"  Saved mapping to {output_path}")


# ===========================
# CLI
# ===========================
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python -m connectors.auto_discover discover --file data.csv")
        print("  python -m connectors.auto_discover wizard --file data.csv")
        print("  python -m connectors.auto_discover wizard --file data.csv --save mapping.json")
        sys.exit(1)

    command = sys.argv[1]
    file_path = None
    save_path = None
    source = "api"

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--file":
            file_path = sys.argv[i + 1]; i += 2
        elif sys.argv[i] == "--save":
            save_path = sys.argv[i + 1]; i += 2
        elif sys.argv[i] == "--source":
            source = sys.argv[i + 1]; i += 2
        else:
            i += 1

    if not file_path:
        print("[!] --file is required")
        sys.exit(1)

    df = pd.read_csv(file_path) if file_path.endswith(".csv") else pd.read_json(file_path, lines=True)
    print(f"Loaded {len(df):,} rows from {file_path}")

    if command == "discover":
        mapping = auto_discover_mapping(df, source)
        print("\nAuto-discovered mapping:")
        for canonical, raw_col in mapping.items():
            print(f"  {raw_col} → {canonical}")
        if save_path:
            save_mapping(mapping, save_path, source)

    elif command == "wizard":
        mapping = run_wizard(df, source)
        if save_path and mapping:
            save_mapping(mapping, save_path, source)

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)
