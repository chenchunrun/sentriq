# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Threat intelligence aggregator.

Aggregates threat intel from multiple sources and calculates
composite threat scores.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional

from shared.utils.logger import get_logger
from shared.utils.time import utc_now_iso

logger = get_logger(__name__)


class ThreatIntelAggregator:
    """
    Aggregates threat intelligence from multiple sources.

    Queries multiple threat intel sources in parallel and aggregates
    results to provide a comprehensive threat assessment.
    """

    # Source weights for aggregation
    SOURCE_WEIGHTS = {
        "virustotal": 0.4,
        "otx": 0.3,
        "abuse_ch": 0.3,
    }

    def __init__(self, sources: List[Any]):
        """
        Initialize aggregator.

        Args:
            sources: List of threat intel source instances
        """
        self.sources = {s.__class__.__name__: s for s in sources}
        logger.info(f"ThreatIntelAggregator initialized with {len(sources)} sources")

    async def query_multiple_sources(
        self,
        ioc: str,
        ioc_type: str = "auto"
    ) -> Dict[str, Any]:
        """
        Query multiple threat intel sources in parallel.

        Args:
            ioc: Indicator of compromise
            ioc_type: IOC type (ip, hash, url, domain, auto)

        Returns:
            Aggregated threat intelligence
        """
        # Query all sources in parallel
        tasks = []
        for source in self.sources.values():
            if source.enabled:
                tasks.append(source.query_ioc(ioc, ioc_type))

        # Wait for all queries to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect successful results
        source_results = {}
        for source_name, result in zip(self.sources.keys(), results):
            if isinstance(result, Exception):
                logger.error(f"Error from {source_name}: {result}")
            elif result is not None:
                source_results[source_name] = result

        # Calculate aggregate score
        aggregate_data = self._calculate_aggregate_score(source_results)

        # Add metadata
        aggregate_data["ioc"] = ioc
        aggregate_data["ioc_type"] = ioc_type
        aggregate_data["queried_sources"] = list(source_results.keys())
        aggregate_data["total_sources"] = len(tasks)
        if aggregate_data["total_sources"] > 0:
            aggregate_data["confidence"] = aggregate_data.get("detected_by_count", 0) / aggregate_data["total_sources"]
        aggregate_data["queried_at"] = utc_now_iso()

        logger.info(
            f"Threat intel aggregated for {ioc}",
            extra={
                "ioc": ioc,
                "sources_queried": len(source_results),
                "aggregate_score": aggregate_data.get("aggregate_score"),
            },
        )

        return aggregate_data

    def _calculate_aggregate_score(self, source_results: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Calculate weighted aggregate threat score.

        Args:
            source_results: Results from multiple sources

        Returns:
            Aggregated threat data with score
        """
        detected_count = 0
        total_count = 0
        weighted_sum = 0.0
        weight_sum = 0.0

        detections = []
        all_tags = set()

        for source_name, result in source_results.items():
            weight = self.SOURCE_WEIGHTS.get(source_name.lower().replace("source", ""), 0.1)

            detected = result.get("detected", False)
            detected_count += 1 if detected else 0
            total_count += 1

            if detected:
                detection_rate = float(result.get("detection_rate", 0) or 0)
                if detection_rate <= 1:
                    detection_rate *= 100
                weighted_sum += max(0.0, min(100.0, detection_rate)) * weight

            weight_sum += weight

            # Collect tags
            if "tags" in result:
                all_tags.update(result.get("tags", []))

            # Record detections
            if detected:
                detections.append({
                    "source": result.get("source", source_name),
                    "detection_rate": result.get("detection_rate", 0),
                })

        # Calculate aggregate score (0-100)
        if weight_sum > 0:
            aggregate_score = weighted_sum / weight_sum
        else:
            aggregate_score = 0

        # Determine threat level
        if aggregate_score >= 70:
            threat_level = "critical"
        elif aggregate_score >= 50:
            threat_level = "high"
        elif aggregate_score >= 30:
            threat_level = "medium"
        elif aggregate_score >= 10:
            threat_level = "low"
        else:
            threat_level = "safe"

        return {
            "aggregate_score": round(aggregate_score, 2),
            "threat_level": threat_level,
            "detected_by_count": detected_count,
            "total_sources": total_count,
            "detections": detections,
            "tags": list(all_tags),
            "confidence": detected_count / total_count if total_count > 0 else 0,
        }

    async def query_batch(
        self,
        iocs: List[str],
        ioc_type: str = "auto"
    ) -> Dict[str, Dict[str, Any]]:
        """
        Query multiple IOCs in parallel.

        Args:
            iocs: List of IOCs to query
            ioc_type: IOC type

        Returns:
            Dictionary mapping IOC to threat intel
        """
        tasks = [self.query_multiple_sources(ioc, ioc_type) for ioc in iocs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return {
            ioc: result if not isinstance(result, Exception) else None
            for ioc, result in zip(iocs, results)
        }

    def get_source_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all sources."""
        stats = {}
        for name, source in self.sources.items():
            stats[name] = {
                "enabled": source.enabled,
                "cache_size": len(getattr(source, "cache", {})),
            }
        return stats
