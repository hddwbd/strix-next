from __future__ import annotations

from collections.abc import Awaitable, Callable
import re
from urllib.parse import urljoin

from .models import PocCandidate, PocExecutionResult, PocRequest


PocTransport = Callable[[PocRequest, str], Awaitable[dict[str, object]]]


def execute_poc_candidates(
    base_url: str,
    candidates: list[PocCandidate],
    response_overrides: dict[str, tuple[int, str, int]] | None = None,
) -> list[PocExecutionResult]:
    results: list[PocExecutionResult] = []
    overrides = response_overrides or {}

    for candidate in candidates:
        if candidate.support_level == "manual_only":
            results.append(
                PocExecutionResult(
                    canonical_id=candidate.canonical_id,
                    status="manual_only",
                    risk_level=candidate.risk_level,
                    support_level=candidate.support_level,
                    reason="manual_only",
                )
            )
            continue

        requests: list[dict[str, object]] = []
        matched = False
        for request in candidate.record.requests:
            url = urljoin(_ensure_trailing_slash(base_url), request.path.lstrip("/"))
            status_code, body, latency = overrides.get(url, (404, "", 0))
            requests.append(_build_http_request_entry(request, url, status_code, latency))
            if _matches(request, status_code, body, latency):
                matched = True
                break

        results.append(
            PocExecutionResult(
                canonical_id=candidate.canonical_id,
                status="executed_hit" if matched else "executed_miss",
                risk_level=candidate.risk_level,
                support_level=candidate.support_level,
                http_requests=requests,
                matched=matched,
            )
        )
    return results


async def execute_poc_candidates_async(
    base_url: str,
    candidates: list[PocCandidate],
    transport: PocTransport,
) -> list[PocExecutionResult]:
    results: list[PocExecutionResult] = []

    for candidate in candidates:
        if candidate.support_level == "manual_only":
            results.append(
                PocExecutionResult(
                    canonical_id=candidate.canonical_id,
                    status="manual_only",
                    risk_level=candidate.risk_level,
                    support_level=candidate.support_level,
                    reason="manual_only",
                )
            )
            continue

        requests: list[dict[str, object]] = []
        matched = False
        error_reason: str | None = None

        for request in candidate.record.requests:
            url = urljoin(_ensure_trailing_slash(base_url), request.path.lstrip("/"))
            response = await transport(request, url)
            status_code = _coerce_status_code(response.get("status_code"))
            latency_ms = _coerce_latency(response.get("latency_ms"))
            request_error = _coerce_optional_str(response.get("error"))

            requests.append(
                _build_http_request_entry(
                    request,
                    url,
                    status_code,
                    latency_ms,
                    request_id=_coerce_optional_str(response.get("request_id")),
                    via_proxy=bool(response.get("via_proxy", False)),
                    error=request_error,
                )
            )

            if request_error:
                error_reason = error_reason or request_error
                continue

            body = str(response.get("body", "") or "")
            if status_code is not None and _matches(request, status_code, body, latency_ms):
                matched = True
                error_reason = None
                break

        status = "executed_hit" if matched else "executed_error" if error_reason else "executed_miss"
        results.append(
            PocExecutionResult(
                canonical_id=candidate.canonical_id,
                status=status,
                risk_level=candidate.risk_level,
                support_level=candidate.support_level,
                http_requests=requests,
                reason=error_reason,
                matched=matched,
            )
        )

    return results


def _matches(request: PocRequest, status_code: int, body: str, latency_ms: int) -> bool:
    matcher = request.matcher
    if "status_in" in matcher:
        allowed = {int(item) for item in matcher["status_in"]}
        if status_code not in allowed:
            return False
    if "body_contains" in matcher:
        if not all(word in body for word in matcher["body_contains"]):
            return False
    expression = str(matcher.get("expression", ""))
    if expression:
        match = re.search(r"response\.status\s*==\s*(\d+)", expression)
        if match and status_code != int(match.group(1)):
            return False
        contains_match = re.search(r'bytes\("([^"]+)"\)', expression)
        if contains_match and contains_match.group(1) not in body:
            return False
        latency_match = re.search(r"response\.latency\s*>=\s*(\d+)", expression)
        if latency_match and latency_ms < int(latency_match.group(1)):
            return False
    response_test = matcher.get("response_test")
    if isinstance(response_test, dict):
        checks = response_test.get("checks", [])
        for check in checks:
            if check.get("variable") == "$code" and status_code != int(check.get("value", 0)):
                return False
    return True


def _ensure_trailing_slash(value: str) -> str:
    return value if value.endswith("/") else f"{value}/"


def _coerce_status_code(value: object) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def _coerce_latency(value: object) -> int:
    if value in (None, ""):
        return 0
    return int(value)


def _coerce_optional_str(value: object) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _build_http_request_entry(
    request: PocRequest,
    url: str,
    status_code: int | None,
    latency_ms: int,
    *,
    request_id: str | None = None,
    via_proxy: bool = False,
    error: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "method": request.method,
        "url": url,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "request_id": request_id,
        "via_proxy": via_proxy,
    }
    if error:
        payload["error"] = error
    return payload
