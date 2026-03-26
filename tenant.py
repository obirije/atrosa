"""
ATROSA Tenant Configuration — Multi-Customer Deployment
==========================================================
Each customer (tenant) has:
  - Their own data source registry (which sources are connected)
  - Schema mappings (column name translations)
  - Noise budget (false positive tolerance)
  - Active hunt categories (which Tier 0-3 categories to run)
  - Isolated rules directory
  - Scoring configuration

Usage:
    tenant = Tenant.load("acme")
    tenant.get_active_hunts()     # Which hunt categories to run
    tenant.get_noise_budget()     # Max flag rate
    tenant.get_schema_normalizer() # Customer-specific column mappings

    # Or create a new tenant
    tenant = Tenant.create("newbank", data_sources=["api", "db", "webhooks", "mobile"])
"""

import json
from pathlib import Path
from typing import Optional


TENANTS_DIR = Path("tenants")


# ===========================
# DATA SOURCE TIERS
# ===========================
TIER_DEFINITIONS = {
    "tier_0": {
        "name": "Universal Telemetry",
        "description": "API gateway, ledger, mobile, webhooks — every customer has these",
        "sources": ["api", "db", "mobile", "webhooks"],
        "hunt_categories": [
            "webhook_desync",
            "toctou_race_condition",
            "business_logic_flaw",
            "reversal_abuse",
            "velocity_anomaly",
        ],
    },
    "tier_1": {
        "name": "Common Enrichment",
        "description": "IP risk, device intel, email risk, SIM/phone intelligence",
        "sources": ["ip_risk", "device_intel", "email_risk", "sim_intel"],
        "hunt_categories": [
            "sim_swap_ato",
            "device_farm_multi_accounting",
            "impossible_travel_cashout",
            "synthetic_identity_onboarding",
            "proxy_credential_stuffing",
            "emulator_promo_abuse",
        ],
    },
    "tier_2": {
        "name": "Identity & Verification",
        "description": "KYC/IDV results, credit bureau, sanctions/PEP, behavioral biometrics",
        "sources": ["kyc_idv", "credit_bureau", "sanctions_pep", "behavioral_biometrics"],
        "hunt_categories": [
            "kyc_gated_cashout",
            "loan_stacking",
            "bust_out_acceleration",
            "authorized_push_payment",
            "sanctions_evasion_layering",
            "deepfake_fast_cashout",
        ],
    },
    "tier_3": {
        "name": "Sector-Specific",
        "description": "Blockchain, insurance, card networks, ACH, consortium, shipping, open banking",
        "sources": [
            "blockchain_analytics", "insurance_claims", "card_network_signals",
            "ach_returns", "consortium_flags", "shipping_delivery", "open_banking",
        ],
        "hunt_categories": [
            "crypto_mixer_layering",
            "ghost_broking",
            "claims_farming",
            "bin_enumeration_escalation",
            "ach_kiting",
            "cross_institution_fraud",
            "inr_chargeback_abuse",
            "income_fabrication",
        ],
    },
}

# Map each source to which enrichment fields it adds
SOURCE_ENRICHMENT_FIELDS = {
    "ip_risk": ["ip_risk_score", "is_vpn", "is_proxy", "is_tor", "is_datacenter", "geo_country", "asn"],
    "device_intel": ["device_id", "is_emulator", "is_rooted", "is_tampered", "device_trust_score"],
    "email_risk": ["email_age_days", "is_disposable", "domain_reputation", "social_profiles_count"],
    "sim_intel": ["line_type", "is_sim_swapped", "carrier", "number_age_days"],
    "kyc_idv": ["verification_status", "document_type", "liveness_score", "match_confidence", "deepfake_detected"],
    "credit_bureau": ["inquiry_count", "thin_file_flag", "credit_age", "address_match", "ssn_issuance_vs_age"],
    "sanctions_pep": ["screening_status", "match_type", "watchlist_name", "risk_level"],
    "behavioral_biometrics": ["session_risk_score", "is_bot", "is_remote_access", "cognitive_stress_flag", "typing_anomaly"],
    "blockchain_analytics": ["wallet_risk_score", "mixer_exposure", "sanctioned_entity_flag", "cluster_id"],
    "insurance_claims": ["prior_claims_count", "claim_type", "siu_referral_flag", "cross_insurer_match"],
    "card_network_signals": ["network_risk_score", "bin_attack_flag", "cross_merchant_velocity"],
    "ach_returns": ["return_code", "return_rate", "originator_risk"],
    "consortium_flags": ["flagged_at_other_institution", "fraud_type", "date_flagged"],
    "shipping_delivery": ["delivery_confirmed", "delivery_address", "signature_obtained"],
    "open_banking": ["verified_income", "source_bank_balances", "transaction_history_months"],
}


class Tenant:
    """Represents a customer deployment of ATROSA."""

    def __init__(self, tenant_id: str, config: dict):
        self.tenant_id = tenant_id
        self.config = config
        self.tenant_dir = TENANTS_DIR / tenant_id

    @classmethod
    def create(cls, tenant_id: str, data_sources: list[str],
               display_name: str = "", noise_budget: float = 0.001,
               sector: str = "fintech") -> "Tenant":
        """Create a new tenant with initial configuration."""
        tenant_dir = TENANTS_DIR / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        (tenant_dir / "rules").mkdir(exist_ok=True)
        (tenant_dir / "hunts").mkdir(exist_ok=True)
        (tenant_dir / "data").mkdir(exist_ok=True)

        # Determine which tiers are active based on connected sources
        active_tiers = cls._resolve_tiers(data_sources)
        active_hunts = cls._resolve_hunts(active_tiers)
        enrichment_fields = cls._resolve_enrichment_fields(data_sources)

        config = {
            "tenant_id": tenant_id,
            "display_name": display_name or tenant_id,
            "sector": sector,
            "created_at": __import__("datetime").datetime.now().isoformat(),
            "data_sources": {
                "connected": data_sources,
                "active_tiers": active_tiers,
                "enrichment_fields": enrichment_fields,
            },
            "scoring": {
                "noise_budget": noise_budget,
                "graduation_threshold": 70,
                "weights": {
                    "statistical": 0.30,
                    "proxy": 0.35,
                    "retroactive": 0.25,
                    "peer": 0.10,
                },
            },
            "hunts": {
                "active_categories": active_hunts,
                "max_iterations": 10,
                "provider": "anthropic",
                "model": "claude-sonnet-4-20250514",
            },
            "schema_mapping_path": str(tenant_dir / "schema_map.json"),
            "rules_path": str(tenant_dir / "rules"),
            "active_rules_path": str(tenant_dir / "active_rules.json"),
        }

        # Save config
        config_path = tenant_dir / "config.json"
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        # Initialize empty active_rules.json
        with open(tenant_dir / "active_rules.json", "w") as f:
            json.dump({"rules": []}, f, indent=2)

        return cls(tenant_id, config)

    @classmethod
    def load(cls, tenant_id: str) -> "Tenant":
        """Load an existing tenant configuration."""
        config_path = TENANTS_DIR / tenant_id / "config.json"
        if not config_path.exists():
            raise FileNotFoundError(f"Tenant '{tenant_id}' not found at {config_path}")
        with open(config_path) as f:
            config = json.load(f)
        return cls(tenant_id, config)

    @classmethod
    def list_tenants(cls) -> list[str]:
        """List all configured tenants."""
        if not TENANTS_DIR.exists():
            return []
        return [d.name for d in TENANTS_DIR.iterdir()
                if d.is_dir() and (d / "config.json").exists()]

    @staticmethod
    def _resolve_tiers(data_sources: list[str]) -> list[str]:
        """Determine which tiers are active based on connected sources."""
        active = ["tier_0"]  # Always active
        for tier_name, tier_def in TIER_DEFINITIONS.items():
            if tier_name == "tier_0":
                continue
            # Tier is active if ANY of its sources are connected
            if any(s in data_sources for s in tier_def["sources"]):
                active.append(tier_name)
        return active

    @staticmethod
    def _resolve_hunts(active_tiers: list[str]) -> list[str]:
        """Determine which hunt categories to run based on active tiers."""
        hunts = []
        for tier_name in active_tiers:
            tier_def = TIER_DEFINITIONS.get(tier_name, {})
            hunts.extend(tier_def.get("hunt_categories", []))
        return hunts

    @staticmethod
    def _resolve_enrichment_fields(data_sources: list[str]) -> dict[str, list[str]]:
        """Map connected sources to the enrichment fields they provide."""
        fields = {}
        for source in data_sources:
            if source in SOURCE_ENRICHMENT_FIELDS:
                fields[source] = SOURCE_ENRICHMENT_FIELDS[source]
        return fields

    # ===========================
    # ACCESSORS
    # ===========================
    def get_active_hunts(self) -> list[str]:
        """Get list of active hunt category IDs for this tenant."""
        return self.config.get("hunts", {}).get("active_categories", [])

    def get_noise_budget(self) -> float:
        """Max flag rate (false positive tolerance)."""
        return self.config.get("scoring", {}).get("noise_budget", 0.001)

    def get_graduation_threshold(self) -> int:
        """Minimum score to graduate a rule."""
        return self.config.get("scoring", {}).get("graduation_threshold", 70)

    def get_scoring_config(self) -> dict:
        """Full scoring configuration."""
        return self.config.get("scoring", {})

    def get_hunt_config(self) -> dict:
        """Hunt orchestrator configuration."""
        return self.config.get("hunts", {})

    def get_connected_sources(self) -> list[str]:
        """List of connected data sources."""
        return self.config.get("data_sources", {}).get("connected", [])

    def get_active_tiers(self) -> list[str]:
        """List of active tier names."""
        return self.config.get("data_sources", {}).get("active_tiers", [])

    def get_enrichment_fields(self) -> dict[str, list[str]]:
        """Map of source → enrichment fields."""
        return self.config.get("data_sources", {}).get("enrichment_fields", {})

    def get_rules_path(self) -> Path:
        """Path to tenant's rules directory."""
        return Path(self.config.get("rules_path", f"tenants/{self.tenant_id}/rules"))

    def get_active_rules_path(self) -> Path:
        """Path to tenant's active_rules.json."""
        return Path(self.config.get("active_rules_path",
                                     f"tenants/{self.tenant_id}/active_rules.json"))

    def get_schema_mapping_path(self) -> Path:
        """Path to tenant's schema mapping config."""
        return Path(self.config.get("schema_mapping_path",
                                     f"tenants/{self.tenant_id}/schema_map.json"))

    # ===========================
    # DATA SOURCE MANAGEMENT
    # ===========================
    def add_source(self, source: str):
        """Connect a new data source and recalculate active hunts."""
        sources = self.get_connected_sources()
        if source not in sources:
            sources.append(source)
            self.config["data_sources"]["connected"] = sources
            self.config["data_sources"]["active_tiers"] = self._resolve_tiers(sources)
            self.config["data_sources"]["enrichment_fields"] = self._resolve_enrichment_fields(sources)
            self.config["hunts"]["active_categories"] = self._resolve_hunts(
                self.config["data_sources"]["active_tiers"]
            )
            self._save()

    def remove_source(self, source: str):
        """Disconnect a data source and recalculate."""
        sources = self.get_connected_sources()
        if source in sources:
            sources.remove(source)
            self.config["data_sources"]["connected"] = sources
            self.config["data_sources"]["active_tiers"] = self._resolve_tiers(sources)
            self.config["data_sources"]["enrichment_fields"] = self._resolve_enrichment_fields(sources)
            self.config["hunts"]["active_categories"] = self._resolve_hunts(
                self.config["data_sources"]["active_tiers"]
            )
            self._save()

    def _save(self):
        """Persist config to disk."""
        config_path = self.tenant_dir / "config.json"
        with open(config_path, "w") as f:
            json.dump(self.config, f, indent=2)

    # ===========================
    # STATUS & REPORTING
    # ===========================
    def status(self) -> dict:
        """Get a summary of tenant status."""
        # Count active rules
        active_rules_path = self.get_active_rules_path()
        rule_count = 0
        if active_rules_path.exists():
            with open(active_rules_path) as f:
                rule_count = len(json.load(f).get("rules", []))

        return {
            "tenant_id": self.tenant_id,
            "display_name": self.config.get("display_name", self.tenant_id),
            "sector": self.config.get("sector", "unknown"),
            "connected_sources": len(self.get_connected_sources()),
            "active_tiers": self.get_active_tiers(),
            "active_hunt_categories": len(self.get_active_hunts()),
            "graduated_rules": rule_count,
            "noise_budget": self.get_noise_budget(),
        }
