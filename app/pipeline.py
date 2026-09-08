"""
Shared scan-and-score orchestration used by both the CLI and the API,
so the exact same sequence runs no matter how WISRA is invoked.

Ordering matters here: fingerprint comparison must happen against the
PREVIOUS baseline stored in the database, so we compute risk
assessments first (which reads the old fingerprint), and only persist
the new observation + advance the fingerprint baseline afterwards.
"""
from typing import List, Optional, Tuple

from app.scanner.models import WiFiNetwork
from app.security.risk_engine import RiskEngine, RiskAssessment
from app.database.database import Database
from app.utils.logger import get_logger

log = get_logger(__name__)


def execute_scan(
    networks: List[WiFiNetwork],
    engine: RiskEngine,
    db: Optional[Database] = None,
) -> List[Tuple[WiFiNetwork, RiskAssessment, Optional[int]]]:
    """
    Scores every network, then (if a Database is provided) persists the
    observation + risk assessment and advances the fingerprint baseline.

    Returns a list of (network, assessment, access_point_id) tuples,
    sorted by risk score descending. access_point_id is None when no
    database is used.
    """
    assessments = engine.assess_batch(networks)

    results = []
    for network, assessment in zip(networks, assessments):
        ap_id = None
        if db is not None:
            ap_id = db.record_observation(network)
            db.save_risk_assessment(ap_id, assessment)
            db.update_fingerprint(network)
        results.append((network, assessment, ap_id))

    results.sort(key=lambda triple: triple[1].score, reverse=True)
    log.info("Pipeline finished: %d network(s) scored.", len(results))
    return results
