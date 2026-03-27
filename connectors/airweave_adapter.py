"""
Airweave Optional Adapter — Pull data from Airweave if running.

Airweave (https://github.com/airweave-ai/airweave) is an open-source
context retrieval layer with 50+ data source connectors. If a customer
runs Airweave alongside ATROSA, this adapter pulls synced data from
Airweave's collections and transforms it into ATROSA's 4 DataFrames.

Airweave is NOT required — this is an optional accelerator. Without it,
ATROSA uses its own direct connectors (Stripe, CSV import, etc.).

The value of Airweave: continuous sync. Airweave keeps data fresh via
Temporal workers, so ATROSA can re-run hunts on current data without
manual exports or API polling.

Usage:
    # Check if Airweave is available
    adapter = AirweaveAdapter()
    if adapter.is_available():
        result = adapter.run(collection="stripe-prod")
        result.save("data/")

    # With custom Airweave URL
    adapter = AirweaveAdapter(
        url="http://airweave.internal:8080",
        api_key="aw_live_...",
    )
"""

import json
import sys
from pathlib import Path
from typing import Optional

import pandas as pd

from .base import BaseConnector, ConnectorResult

sys.path.insert(0, str(Path(__file__).parent.parent))
from schema_normalizer import SchemaNormalizer


class AirweaveAdapter(BaseConnector):
    """Optional: pulls data from Airweave if available."""

    name = "airweave"
    description = "Pull from Airweave data sync layer (optional)"

    DEFAULT_URL = "http://localhost:8080"

    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None,
                 collection: Optional[str] = None):
        self.url = (url or self.DEFAULT_URL).rstrip("/")
        self.api_key = api_key
        self.collection = collection
        self._entities: list[dict] = []

    def is_available(self) -> bool:
        """Check if Airweave is running and reachable."""
        import urllib.request
        try:
            req = urllib.request.Request(f"{self.url}/health")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            return False

    def list_collections(self) -> list[dict]:
        """List available Airweave collections."""
        return self._api_get("/api/v1/collections") or []

    def pull(self) -> pd.DataFrame:
        """Pull entities from an Airweave collection."""
        if not self.collection:
            raise ValueError("No collection specified. Use --collection <name>")

        if not self.is_available():
            raise ConnectionError(
                f"Airweave not reachable at {self.url}. "
                f"Either start Airweave or use a different connector (--source csv, --source stripe)."
            )

        # Get all entities from the collection
        entities = self._api_get(f"/api/v1/collections/{self.collection}/entities")
        if not entities:
            print(f"    [!] No entities found in collection '{self.collection}'")
            collections = self.list_collections()
            if collections:
                names = [c.get("readable_id", c.get("id", "?")) for c in collections]
                print(f"    Available collections: {names}")
            return pd.DataFrame()

        self._entities = entities
        print(f"    Pulled {len(entities)} entities from collection '{self.collection}'")

        # Flatten entities into a DataFrame
        records = []
        for entity in entities:
            record = self._flatten_entity(entity)
            records.append(record)

        return pd.DataFrame(records)

    def transform(self, raw: pd.DataFrame) -> ConnectorResult:
        """Transform Airweave entities into ATROSA's 4 DataFrames."""
        if raw.empty:
            return ConnectorResult(
                api=pd.DataFrame(), db=pd.DataFrame(),
                mobile=pd.DataFrame(), webhooks=pd.DataFrame(),
            )

        # Auto-discover schema mapping
        normalizer = SchemaNormalizer.auto_discover({"api": raw})

        # Classify entities by type if Airweave provides entity_type
        if "_entity_type" in raw.columns:
            return self._transform_by_type(raw, normalizer)

        # Otherwise, put all data into api + db (most common for payment data)
        normalized = normalizer.normalize(raw, "api")

        return ConnectorResult(
            api=normalized,
            db=normalizer.normalize(raw, "db"),
            mobile=pd.DataFrame(),
            webhooks=normalizer.normalize(raw, "webhooks"),
            metadata={
                "connector": self.name,
                "collection": self.collection,
                "airweave_url": self.url,
                "entities_pulled": len(raw),
            },
        )

    def _transform_by_type(self, raw: pd.DataFrame, normalizer: SchemaNormalizer) -> ConnectorResult:
        """Transform when entities have type annotations from Airweave."""
        # Map Airweave entity types to ATROSA sources
        type_to_source = {
            # Stripe entity types
            "StripeChargeEntity": "db",
            "StripePaymentIntentEntity": "api",
            "StripeRefundEntity": "db",
            "StripeDisputeEntity": "webhooks",
            "StripeCustomerEntity": "mobile",
            "StripeEventEntity": "webhooks",
            # Generic types
            "transaction": "db",
            "payment": "api",
            "refund": "db",
            "event": "webhooks",
            "user": "mobile",
        }

        sources = {"api": [], "db": [], "mobile": [], "webhooks": []}

        for entity_type in raw["_entity_type"].unique():
            source = type_to_source.get(entity_type, "db")
            mask = raw["_entity_type"] == entity_type
            chunk = raw[mask].drop(columns=["_entity_type"], errors="ignore")
            sources[source].append(normalizer.normalize(chunk, source))

        result_sources = {}
        for source, chunks in sources.items():
            if chunks:
                result_sources[source] = pd.concat(chunks, ignore_index=True)
            else:
                result_sources[source] = pd.DataFrame()

        return ConnectorResult(
            api=result_sources["api"],
            db=result_sources["db"],
            mobile=result_sources["mobile"],
            webhooks=result_sources["webhooks"],
            metadata={
                "connector": self.name,
                "collection": self.collection,
                "entity_types": raw["_entity_type"].value_counts().to_dict(),
            },
        )

    def _api_get(self, endpoint: str) -> Optional[list]:
        """Make a GET request to Airweave API."""
        import urllib.request

        url = f"{self.url}{endpoint}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                if isinstance(data, list):
                    return data
                return data.get("data", data.get("results", []))
        except Exception as e:
            print(f"    [!] Airweave API error: {e}")
            return None

    @staticmethod
    def _flatten_entity(entity: dict) -> dict:
        """Flatten an Airweave entity into a flat dict."""
        flat = {}

        # Preserve entity type for source classification
        flat["_entity_type"] = entity.get("entity_type", entity.get("type", "unknown"))

        # Flatten top-level fields
        for key, value in entity.items():
            if isinstance(value, dict):
                for k2, v2 in value.items():
                    flat[f"{key}_{k2}"] = v2
            elif isinstance(value, list):
                flat[key] = json.dumps(value)
            else:
                flat[key] = value

        return flat
