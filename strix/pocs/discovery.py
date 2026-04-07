from __future__ import annotations

from dataclasses import dataclass

from .models import (
    FingerprintEvidence,
    PocCandidate,
    PocDiscoverResult,
    PocRecord,
    SkippedCandidate,
)


_RISK_ORDER = {
    "discovery": 0,
    "read_only": 1,
    "timing": 2,
    "oob_safe": 3,
    "auth_state_change": 4,
    "write": 5,
    "upload": 6,
    "delete": 7,
    "exec": 8,
}


def discover_pocs(
    records: list[PocRecord],
    evidence: FingerprintEvidence,
    batch_size: int = 3,
    risk_ceiling: str = "read_only",
    cursor: int = 0,
) -> PocDiscoverResult:
    eligible: list[PocCandidate] = []
    skipped: list[SkippedCandidate] = []

    for record in records:
        reasons = _match_reasons(record, evidence)
        if not reasons:
            continue
        if _RISK_ORDER[record.risk_level] > _RISK_ORDER[risk_ceiling]:
            skipped.append(
                SkippedCandidate(
                    canonical_id=record.canonical_id,
                    reason="risk_ceiling",
                    risk_level=record.risk_level,
                )
            )
            continue
        score = len(reasons) * 10
        if record.support_level == "manual_only":
            score -= 5
        eligible.append(
            PocCandidate(
                canonical_id=record.canonical_id,
                name=record.name,
                source=record.source,
                risk_level=record.risk_level,
                support_level=record.support_level,
                score=score,
                match_reasons=reasons,
                record=record,
            )
        )

    eligible.sort(key=lambda item: (-item.score, item.canonical_id))
    candidates = eligible[cursor : cursor + batch_size]
    next_cursor = cursor + batch_size if cursor + batch_size < len(eligible) else None
    return PocDiscoverResult(candidates=candidates, skipped=skipped, next_cursor=next_cursor)


def _match_reasons(record: PocRecord, evidence: FingerprintEvidence) -> list[str]:
    reasons: list[str] = []
    keywords = {keyword.lower() for keyword in record.match_signals.get("keywords", [])}

    if evidence.product and evidence.product.lower() in keywords:
        reasons.append(f"product:{evidence.product}")
    if evidence.component and evidence.component.lower() in keywords and not reasons:
        reasons.append(f"component:{evidence.component}")
    if evidence.title:
        title_lower = evidence.title.lower()
        for keyword in keywords:
            if keyword and keyword in title_lower:
                reasons.append(f"title:{keyword}")
                break
    if evidence.path and any(request.path == evidence.path or request.path == "/" for request in record.requests):
        reasons.append(f"path:{evidence.path}")
    if evidence.version and record.version and evidence.version == record.version:
        reasons.append(f"version:{evidence.version}")

    deduped: list[str] = []
    for reason in reasons:
        if reason not in deduped:
            deduped.append(reason)
    return deduped
