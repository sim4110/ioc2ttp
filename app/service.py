#Malware Bazaar API
"""MalwareBazaar Community API client.

https://bazaar.abuse.ch/api/ 문서 기준. 모든 요청은 POST + form-data이며,
2024년 이후로는 Auth-Key 헤더가 필수다.
"""
import requests

API_URL = "https://mb-api.abuse.ch/api/v1/"
TIMEOUT = 30


class MalwareBazaarError(RuntimeError):
    pass


def _post(data: dict, api_key: str) -> dict:
    if not api_key or api_key == "your_api_key_here":
        raise MalwareBazaarError(
            "MALWAREBAZAAR_API_KEY가 설정되지 않았습니다. .env 파일을 확인하세요."
        )
    resp = requests.post(
        API_URL, data=data, headers={"Auth-Key": api_key}, timeout=TIMEOUT
    )
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("query_status") not in ("ok",):
        # query_status에는 no_results, illegal_hash 등 다양한 상태가 올 수 있다.
        payload.setdefault("data", [])
    return payload


def get_recent(api_key: str, selector: str = "100") -> list:
    """최근 탐지된 샘플 목록. selector: 최대 1000, 또는 'time'(최근 60분)."""
    payload = _post({"query": "get_recent", "selector": selector}, api_key)
    return payload.get("data", [])


def get_taginfo(api_key: str, tag: str, limit: int = 1000) -> list:
    """특정 태그(패밀리/APT 그룹 등)로 태깅된 샘플 목록."""
    payload = _post(
        {"query": "get_taginfo", "tag": tag, "limit": str(limit)}, api_key
    )
    return payload.get("data", [])


def get_info(api_key: str, sha256_hash: str) -> dict:
    """단일 샘플 상세 조회."""
    payload = _post({"query": "get_info", "hash": sha256_hash}, api_key)
    data = payload.get("data", [])
    return data[0] if data else {}


def parse_enrichment(info: dict) -> dict:
    """get_info() 응답에서 상세조회 화면에 쓸 보강 필드를 뽑아낸다.

    배치 수집(collectors/malwarebazaar_collector.py)과 상세조회 실시간 보완
    (app/model.py)이 이 로직을 공유해 추출 결과가 항상 일치하도록 한다.
    """
    yara_rules = info.get("yara_rules") or []
    triage = ((info.get("vendor_intel") or {}).get("Triage")) or {}

    behaviors = [
        {"behavior": s.get("signature", "").strip(), "score": s.get("score") or ""}
        for s in (triage.get("signatures") or [])
        if s.get("signature")
    ]
    references = [
        {"context": r.get("context", ""), "value": r.get("value", "")}
        for r in (info.get("file_information") or [])
        if r.get("value")
    ]

    return {
        "yara_rule_names": [r.get("rule_name", "") for r in yara_rules if r.get("rule_name")],
        "imphash": info.get("imphash") or "",
        "tlsh": info.get("tlsh") or "",
        "ssdeep": info.get("ssdeep") or "",
        "reporter": info.get("reporter") or "",
        "vendor_family": triage.get("malware_family") or "",
        "vendor_score": triage.get("score") or "",
        "behaviors": behaviors,
        "references": references,
    }
