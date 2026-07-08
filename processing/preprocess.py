"""데이터 전처리 (project.pdf 3-1, 3-2).

data/raw의 원본 CSV 3종(malwarebazaar, loldrivers, mitre attack)을 읽어
DB 스키마에 바로 적재 가능한 형태로 정제한 뒤 data/processed에 저장한다.
"""
import csv
import os
import re
from datetime import datetime

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "processed")


def normalize_key(name: str) -> str:
    """ATT&CK 매핑용 키 정규화: 소문자화 + 영숫자만 남김."""
    if not name:
        return ""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def normalize_hash(value: str) -> str:
    return (value or "").strip().lower()


def normalize_datetime(value: str) -> str:
    """MalwareBazaar의 'YYYY-MM-DD HH:MM:SS[ UTC]' 등을 ISO 8601로 통일."""
    if not value:
        return ""
    value = value.strip().replace(" UTC", "").replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    return value  # 파싱 실패 시 원본 유지


def _read_csv(path: str) -> list:
    if not os.path.exists(path):
        return []
    with open(path, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _write_csv(path: str, fieldnames: list, rows: list) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def process_samples():
    rows = _read_csv(os.path.join(RAW_DIR, "malwarebazaar_samples.csv"))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    samples, yara_matches, behaviors, references = [], [], [], []

    for r in rows:
        sha256 = normalize_hash(r.get("sha256_hash"))
        if not sha256:
            continue
        signature = (r.get("signature") or "").strip() or "unclassified"
        is_enriched = (r.get("enriched") or "0") == "1"

        samples.append({
            "sha256_hash": sha256,
            "md5_hash": normalize_hash(r.get("md5_hash")),
            "sha1_hash": normalize_hash(r.get("sha1_hash")),
            "file_name": r.get("file_name", ""),
            "file_size": r.get("file_size") or 0,
            "file_type": r.get("file_type", ""),
            "signature": signature,
            "tags": r.get("tags", ""),
            "first_seen": normalize_datetime(r.get("first_seen", "")),
            "last_seen": normalize_datetime(r.get("last_seen", "")),
            "delivery_method": r.get("delivery_method", ""),
            "origin_country": r.get("origin_country", ""),
            "code_sign": r.get("code_sign", ""),
            "imphash": r.get("imphash", ""),
            "tlsh": r.get("tlsh", ""),
            "ssdeep": r.get("ssdeep", ""),
            "reporter": r.get("reporter", ""),
            "vendor_family": r.get("vendor_family", ""),
            "vendor_score": r.get("vendor_score") or "",
            "enriched_at": now if is_enriched else "",
        })

        for rule_name in (r.get("yara_rule_names") or "").split(";"):
            rule_name = rule_name.strip()
            if rule_name:
                yara_matches.append({"sha256_hash": sha256, "rule_name": rule_name})

        for item in (r.get("behaviors") or "").split(";"):
            if "::" not in item:
                continue
            behavior, score = item.split("::", 1)
            behavior = behavior.strip()
            score = score.strip()
            if score in ("", "None"):
                score = ""
            if behavior:
                behaviors.append({"sha256_hash": sha256, "behavior": behavior, "score": score})

        for item in (r.get("references") or "").split(";"):
            if "::" not in item:
                continue
            context, value = item.split("::", 1)
            value = value.strip()
            if value:
                references.append({"sha256_hash": sha256, "context": context.strip(), "value": value})

    _write_csv(
        os.path.join(PROCESSED_DIR, "samples.csv"),
        ["sha256_hash", "md5_hash", "sha1_hash", "file_name", "file_size",
         "file_type", "signature", "tags", "first_seen", "last_seen",
         "delivery_method", "origin_country", "code_sign",
         "imphash", "tlsh", "ssdeep", "reporter", "vendor_family",
         "vendor_score", "enriched_at"],
        samples,
    )
    _write_csv(
        os.path.join(PROCESSED_DIR, "yara_matches.csv"),
        ["sha256_hash", "rule_name"],
        yara_matches,
    )
    _write_csv(
        os.path.join(PROCESSED_DIR, "sample_behaviors.csv"),
        ["sha256_hash", "behavior", "score"],
        behaviors,
    )
    _write_csv(
        os.path.join(PROCESSED_DIR, "sample_references.csv"),
        ["sha256_hash", "context", "value"],
        references,
    )
    print(
        f"[preprocess] samples: {len(samples)}, yara_matches: {len(yara_matches)}, "
        f"behaviors: {len(behaviors)}, references: {len(references)}"
    )
    return samples


def process_drivers():
    rows = _read_csv(os.path.join(RAW_DIR, "loldrivers_samples.csv"))
    drivers, seen = [], set()

    for r in rows:
        sha256 = normalize_hash(r.get("driver_sha256"))
        if not sha256 or sha256 in seen:
            continue
        seen.add(sha256)
        drivers.append({
            "hash_sha256": sha256,
            "driver_name": r.get("filename", ""),
            "category": (r.get("category") or "").strip().lower(),
            "cve_id": r.get("cve_id", ""),
            "publisher": r.get("publisher") or r.get("company") or "",
            "source": "loldrivers",
        })

    _write_csv(
        os.path.join(PROCESSED_DIR, "vulnerable_drivers.csv"),
        ["hash_sha256", "driver_name", "category", "cve_id", "publisher", "source"],
        drivers,
    )
    print(f"[preprocess] vulnerable_drivers: {len(drivers)}")


def build_attack_lookup() -> dict:
    """정규화된 소프트웨어명/별칭 -> [(technique_id, technique_name, tactic, software_name), ...]"""
    rows = _read_csv(os.path.join(RAW_DIR, "attack_software_technique.csv"))
    lookup = {}
    for r in rows:
        entry = (r["technique_id"], r["technique_name"], r["tactic"], r["software_name"])
        names = [r["software_name"]] + [a for a in (r.get("aliases") or "").split(";") if a]
        for name in names:
            key = normalize_key(name)
            if not key:
                continue
            lookup.setdefault(key, []).append(entry)
    return lookup


def build_alias_clusters() -> dict:
    """MISP Galaxy(Malpedia) 별칭 크로스워크를 정규화된 키 기준 동치 클래스로 구성.

    ATT&CK의 x_mitre_aliases는 구조화된 별칭이 부실해 (예: Emotet에 'Heodo' 누락),
    signature 이름 자체를 이 클러스터로 먼저 확장한 뒤 ATT&CK 룩업을 시도한다.
    반환값: normalize_key(name) -> 같은 클러스터에 속한 모든 정규화 키 집합
    """
    rows = _read_csv(os.path.join(RAW_DIR, "malpedia_aliases.csv"))
    cluster_of = {}   # norm_key -> cluster_id
    members_of = {}   # cluster_id -> set(norm_key)

    for r in rows:
        canonical_id = normalize_key(r["canonical_name"])
        alias_key = normalize_key(r["alias_name"])
        if not canonical_id or not alias_key:
            continue
        cluster_of[alias_key] = canonical_id
        members_of.setdefault(canonical_id, set()).add(alias_key)

    key_to_members = {}
    for norm_key, cluster_id in cluster_of.items():
        key_to_members[norm_key] = members_of[cluster_id]
    return key_to_members


def process_attack_mapping(samples: list):
    lookup = build_attack_lookup()
    alias_clusters = build_alias_clusters()
    mapping_rows = []
    matched_signatures = set()
    matched_via_alias = set()

    signatures = {s["signature"] for s in samples if s["signature"] != "unclassified"}
    for signature in signatures:
        norm = normalize_key(signature)
        candidate_keys = {norm} | alias_clusters.get(norm, set())

        seen_entries = set()
        direct_hit = norm in lookup
        for candidate in candidate_keys:
            for technique_id, technique_name, tactic, software_name in lookup.get(candidate, []):
                dedup_key = (technique_id, tactic, software_name)
                if dedup_key in seen_entries:
                    continue
                seen_entries.add(dedup_key)
                mapping_rows.append({
                    "signature": signature,
                    "software_name": software_name,
                    "technique_id": technique_id,
                    "technique_name": technique_name,
                    "tactic": tactic,
                })

        if seen_entries:
            matched_signatures.add(signature)
            if not direct_hit:
                matched_via_alias.add(signature)

    _write_csv(
        os.path.join(PROCESSED_DIR, "attack_ttp_mapping.csv"),
        ["signature", "software_name", "technique_id", "technique_name", "tactic"],
        mapping_rows,
    )

    match_rate = (len(matched_signatures) / len(signatures) * 100) if signatures else 0
    print(
        f"[preprocess] attack_ttp_mapping rows: {len(mapping_rows)}, "
        f"매칭 signature: {len(matched_signatures)}/{len(signatures)} ({match_rate:.1f}%), "
        f"별칭 확장으로 추가 매칭: {len(matched_via_alias)}건 {sorted(matched_via_alias)}"
    )


def _resolve_group_for_tag(tag: str, group_aliases: dict) -> str:
    """우리가 수집에 쓴 APT 태그(예: 'Lazarus')를 MITRE Group 정식명(예: 'Lazarus Group')에
    대응시킨다. 정확히 일치하는 별칭이 없으면(예: 'Lazarus' vs 'Lazarus Group') 부분
    문자열 포함 관계로 한 번 더 시도한다."""
    tag_key = normalize_key(tag)
    if not tag_key:
        return ""

    for group_name, aliases in group_aliases.items():
        names = [group_name] + [a for a in (aliases or "").split(";") if a]
        if any(normalize_key(name) == tag_key for name in names):
            return group_name

    for group_name, aliases in group_aliases.items():
        names = [group_name] + [a for a in (aliases or "").split(";") if a]
        for name in names:
            norm_name = normalize_key(name)
            if norm_name and (tag_key in norm_name or norm_name in tag_key):
                return group_name
    return ""


def process_group_mapping():
    """MITRE ATT&CK Group(intrusion-set)의 attack chain 데이터를 그대로 옮기고,
    우리가 수집한 APT 태그를 MITRE Group 정식명에 매핑해둔다 (5장 그룹별 분석용)."""
    from collectors.malwarebazaar_collector import APT_TAGS

    rows = _read_csv(os.path.join(RAW_DIR, "attack_group_technique.csv"))

    group_aliases = {}
    for r in rows:
        group_aliases.setdefault(r["group_name"], r["aliases"])

    resolution_rows = [
        {"local_tag": tag, "mitre_group_name": _resolve_group_for_tag(tag, group_aliases)}
        for tag in APT_TAGS
    ]

    _write_csv(
        os.path.join(PROCESSED_DIR, "attack_group_technique.csv"),
        ["group_name", "aliases", "technique_id", "technique_name", "tactic", "via_software"],
        rows,
    )
    _write_csv(
        os.path.join(PROCESSED_DIR, "group_tag_resolution.csv"),
        ["local_tag", "mitre_group_name"],
        resolution_rows,
    )

    resolved = {r["local_tag"]: r["mitre_group_name"] for r in resolution_rows if r["mitre_group_name"]}
    print(
        f"[preprocess] attack_group_technique: {len(rows)} rows ({len(group_aliases)} groups), "
        f"태그 매칭: {len(resolved)}/{len(APT_TAGS)} {resolved}"
    )


def run():
    samples = process_samples()
    process_drivers()
    process_attack_mapping(samples)
    process_group_mapping()


if __name__ == "__main__":
    run()
