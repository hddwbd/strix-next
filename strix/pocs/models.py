from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


PocSource = Literal["xray", "nuclei", "goby", "custom"]
PocSupportLevel = Literal["auto", "manual_only"]
PocRiskLevel = Literal[
    "discovery",
    "read_only",
    "timing",
    "oob_safe",
    "auth_state_change",
    "write",
    "upload",
    "delete",
    "exec",
]
ExecutionStatus = Literal[
    "disclosed",
    "manual_only",
    "skipped_risk",
    "executed_hit",
    "executed_miss",
    "executed_error",
]


@dataclass(slots=True)
class PocRequest:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    matcher: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PocRecord:
    canonical_id: str
    source: PocSource
    source_path: str
    name: str
    component: str
    product: str
    version: str | None
    protocol: str
    risk_level: PocRiskLevel
    support_level: PocSupportLevel
    tags: list[str] = field(default_factory=list)
    match_signals: dict[str, list[str]] = field(default_factory=dict)
    requests: list[PocRequest] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["source_path"] = self.source_path
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PocRecord":
        requests = [PocRequest(**item) for item in data.get("requests", [])]
        payload = dict(data)
        payload["requests"] = requests
        return cls(**payload)


@dataclass(slots=True)
class FingerprintEvidence:
    component: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    title: str | None = None
    server: str | None = None
    path: str | None = None
    port: int | None = None
    source: str | None = None


@dataclass(slots=True)
class PocCandidate:
    canonical_id: str
    name: str
    source: PocSource
    risk_level: PocRiskLevel
    support_level: PocSupportLevel
    score: int
    match_reasons: list[str]
    record: PocRecord


@dataclass(slots=True)
class SkippedCandidate:
    canonical_id: str
    reason: str
    risk_level: PocRiskLevel


@dataclass(slots=True)
class PocDiscoverResult:
    candidates: list[PocCandidate]
    skipped: list[SkippedCandidate]
    next_cursor: int | None


@dataclass(slots=True)
class PocExecutionResult:
    canonical_id: str
    status: ExecutionStatus
    risk_level: PocRiskLevel
    support_level: PocSupportLevel
    http_requests: list[dict[str, Any]] = field(default_factory=list)
    reason: str | None = None
    matched: bool = False


def make_canonical_id(source: str, path: Path) -> str:
    stem = path.stem.lower().replace("_", "-").replace(" ", "-")
    return f"{source}:{stem}"
