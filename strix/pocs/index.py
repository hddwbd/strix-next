from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .models import PocRecord, PocRequest, make_canonical_id


def build_poc_index(poc_root: Path, cache_path: Path | None = None) -> list[PocRecord]:
    records: list[PocRecord] = []
    for path in sorted(poc_root.rglob("*")):
        if not path.is_file():
            continue
        record = _parse_path(poc_root, path)
        if record is not None:
            records.append(record)

    if cache_path is not None:
        cache_path.write_text(
            json.dumps([record.to_dict() for record in records], indent=2),
            encoding="utf-8",
        )
    return records


def load_poc_index(poc_root: Path, cache_path: Path | None = None) -> list[PocRecord]:
    if cache_path is not None and cache_path.exists():
        payload = json.loads(cache_path.read_text(encoding="utf-8"))
        return [PocRecord.from_dict(item) for item in payload]
    return build_poc_index(poc_root, cache_path=cache_path)


def _parse_path(poc_root: Path, path: Path) -> PocRecord | None:
    relative = path.relative_to(poc_root)
    parts = relative.parts
    if not parts:
        return None

    source_dir = parts[0]
    if source_dir == "xray":
        return _parse_yaml_record("xray", path, relative)
    if source_dir == "nuclei" and path.suffix in {".yaml", ".yml"}:
        return _parse_nuclei_record(path, relative)
    if source_dir == "goby-poc":
        if path.suffix == ".json":
            return _parse_goby_record(path, relative)
        return _manual_only_record("goby", path, relative)
    if source_dir == "custom":
        return _parse_yaml_record("custom", path, relative)
    return None


def _parse_yaml_record(source: str, path: Path, relative: Path) -> PocRecord:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    detail = data.get("detail", {}) or {}
    description = str(detail.get("description", data.get("name", path.stem)))
    component = _detect_component([path.stem, description, str(relative)])
    requests = []
    for rule in (data.get("rules", {}) or {}).values():
        request = (rule or {}).get("request", {})
        if request:
            requests.append(
                PocRequest(
                    method=str(request.get("method", "GET")).upper(),
                    path=str(request.get("path", "/")),
                    headers=dict(request.get("headers", {}) or {}),
                    body=str(request.get("body", "")),
                    matcher={"expression": str((rule or {}).get("expression", ""))},
                )
            )

    return PocRecord(
        canonical_id=make_canonical_id(source, path),
        source=source,
        source_path=str(relative),
        name=str(data.get("name", path.stem)),
        component=component,
        product=component,
        version=_detect_version([path.stem, description]),
        protocol=str(data.get("transport", "http")),
        risk_level=_infer_risk_level(path.stem, description, []),
        support_level="auto",
        tags=[],
        match_signals={"keywords": [component.lower()] if component else []},
        requests=requests,
        metadata={"description": description, "author": detail.get("author")},
    )


def _parse_nuclei_record(path: Path, relative: Path) -> PocRecord:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    info = data.get("info", {}) or {}
    metadata = info.get("metadata", {}) or {}
    component = _detect_component(
        [
            str(info.get("name", path.stem)),
            str(metadata.get("product", "")),
            str(metadata.get("vendor", "")),
            str(relative),
        ]
    )
    requests = []
    for item in data.get("http", []) or []:
        matchers = item.get("matchers", []) or []
        matcher: dict[str, Any] = {}
        for matcher_item in matchers:
            if matcher_item.get("type") == "word":
                matcher["body_contains"] = list(matcher_item.get("words", []))
            if matcher_item.get("type") == "status":
                matcher["status_in"] = list(matcher_item.get("status", []))
        first_path = "/"
        paths = item.get("path", []) or []
        if paths:
            first_path = str(paths[0]).replace("{{BaseURL}}", "")
        requests.append(
            PocRequest(
                method=str(item.get("method", "GET")).upper(),
                path=first_path or "/",
                matcher=matcher,
            )
        )

    tags = [tag.strip() for tag in str(info.get("tags", "")).split(",") if tag.strip()]
    return PocRecord(
        canonical_id=make_canonical_id("nuclei", path),
        source="nuclei",
        source_path=str(relative),
        name=str(info.get("name", path.stem)),
        component=component,
        product=str(metadata.get("product", component)),
        version=None,
        protocol="http",
        risk_level=_infer_risk_level(path.stem, str(info.get("name", "")), tags),
        support_level="auto",
        tags=tags,
        match_signals={"keywords": [component.lower()] if component else []},
        requests=requests,
        metadata={"severity": info.get("severity"), "id": data.get("id")},
    )


def _parse_goby_record(path: Path, relative: Path) -> PocRecord:
    data = json.loads(path.read_text(encoding="utf-8"))
    component = _detect_component(
        [
            str(data.get("Product", "")),
            str(data.get("Name", "")),
            str(data.get("Description", "")),
        ]
    )
    requests = []
    for item in data.get("ScanSteps") or []:
        if not isinstance(item, dict):
            continue
        request = item.get("Request", {})
        if not request:
            continue
        requests.append(
            PocRequest(
                method=str(request.get("method", "GET")).upper(),
                path=str(request.get("uri", "/")),
                headers=dict(request.get("header", {}) or {}),
                body=str(request.get("data", "")),
                matcher={"response_test": item.get("ResponseTest", {})},
            )
        )

    tags = [str(tag) for tag in data.get("Tags") or []]
    return PocRecord(
        canonical_id=make_canonical_id("goby", path),
        source="goby",
        source_path=str(relative),
        name=str(data.get("Name", path.stem)),
        component=component,
        product=str(data.get("Product", component)),
        version=None,
        protocol="http",
        risk_level=_infer_risk_level(path.stem, str(data.get("Description", "")), tags),
        support_level="auto",
        tags=tags,
        match_signals={"keywords": [component.lower()] if component else []},
        requests=requests,
        metadata={"description": data.get("Description")},
    )


def _manual_only_record(source: str, path: Path, relative: Path) -> PocRecord:
    component = _detect_component([path.stem, str(relative)])
    return PocRecord(
        canonical_id=make_canonical_id(source, path),
        source=source,  # type: ignore[arg-type]
        source_path=str(relative),
        name=path.stem,
        component=component,
        product=component,
        version=None,
        protocol="unknown",
        risk_level="read_only",
        support_level="manual_only",
        tags=[],
        match_signals={"keywords": [component.lower()] if component else []},
        requests=[],
        metadata={"reason": "unsupported_format"},
    )


def _detect_component(values: list[str]) -> str:
    normalized = " ".join(value for value in values if value).lower()
    if "zeroshell" in normalized:
        return "ZeroShell"
    if "nacos" in normalized:
        return "Nacos"
    if "vmware" in normalized:
        return "VMware vCenter"
    if "wifisky" in normalized:
        return "WiFiSky"
    return values[0] if values and values[0] else "Unknown"


def _detect_version(values: list[str]) -> str | None:
    normalized = " ".join(value for value in values if value).lower()
    if "3.9.0" in normalized:
        return "3.9.0"
    return None


def _infer_risk_level(name: str, description: str, tags: list[str]) -> str:
    haystack = " ".join([name, description, *tags]).lower()
    if "panel" in haystack or "discovery" in haystack or "detect" in haystack:
        return "discovery"
    if "rce" in haystack or "remote code execution" in haystack:
        return "exec"
    if "default password" in haystack or "login" in haystack:
        return "auth_state_change"
    if "upload" in haystack:
        return "upload"
    if "delete" in haystack:
        return "delete"
    if "time" in haystack or "sleep" in haystack:
        return "timing"
    return "read_only" if "read" in haystack or "panel" in haystack else "discovery"
