#postgresql db function
"""대시보드가 필요로 하는 집계 쿼리 모음 (project.pdf 4-2, 5-2)."""
import os

import psycopg2
import psycopg2.extras
from psycopg2.extras import execute_values

from app import service

# MITRE ATT&CK Enterprise kill chain 순서. attack chain을 실제 공격 진행 단계
# 순서대로 보여주기 위한 정렬 기준 (문서화되지 않은 tactic은 뒤로 밀린다).
# 참고: MITRE가 기존 'defense-evasion' 단일 tactic을 'stealth'(은폐 기법)와
# 'defense-impairment'(방어 무력화)로 세분화해, 현재 raw 데이터에는 defense-evasion이
# 더 이상 등장하지 않는다. 두 tactic 모두 옛 defense-evasion 자리(권한상승 다음)에 둔다.
KILL_CHAIN_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "stealth", "defense-impairment",
    "credential-access", "discovery", "lateral-movement", "collection",
    "command-and-control", "exfiltration", "impact",
]


def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "cti_dashboard"),
        user=os.getenv("DB_USER", "cti_user"),
        password=os.getenv("DB_PASSWORD", "cti_password"),
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def _query(sql: str, params: tuple = ()) -> list:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_meta() -> dict:
    rows = _query("""
        SELECT
            (SELECT COUNT(*) FROM samples) AS sample_count,
            (SELECT COUNT(*) FROM vulnerable_drivers) AS driver_count,
            (SELECT COUNT(DISTINCT signature) FROM attack_ttp_mapping) AS matched_signatures,
            (SELECT MIN(first_seen) FROM samples) AS earliest_seen,
            (SELECT MAX(first_seen) FROM samples) AS latest_seen
    """)
    return rows[0] if rows else {}


def get_top_signatures(n: int = 10) -> list:
    return _query("""
        SELECT signature, COUNT(*) AS count
        FROM samples
        WHERE signature <> 'unclassified'
        GROUP BY signature
        ORDER BY count DESC
        LIMIT %s
    """, (n,))


def get_top_yara_rules(n: int = 10) -> list:
    return _query("""
        SELECT rule_name, COUNT(*) AS count
        FROM yara_matches
        GROUP BY rule_name
        ORDER BY count DESC
        LIMIT %s
    """, (n,))


def get_timeseries() -> list:
    return _query("""
        SELECT DATE(first_seen) AS date, COUNT(*) AS count
        FROM samples
        WHERE first_seen IS NOT NULL
        GROUP BY DATE(first_seen)
        ORDER BY date
    """)


def get_filetype_distribution() -> list:
    return _query("""
        SELECT COALESCE(NULLIF(file_type, ''), 'unknown') AS file_type, COUNT(*) AS count
        FROM samples
        GROUP BY file_type
        ORDER BY count DESC
    """)


def _live_enrich(sha256_hash: str) -> dict:
    """배치 수집 시 보강 대상에서 빠진 샘플을 상세조회 시점에 즉석으로 보완한다.

    DB에는 저장하지 않고(다음 배치 재수집 전까지는 매번 재요청), 이번 응답에만 반영한다.
    API 키가 없거나 MalwareBazaar 요청이 실패해도 조용히 빈 값으로 넘어간다
    (상세조회 자체는 DB에 있는 기본 정보만으로도 동작해야 하므로).
    """
    api_key = os.getenv("MALWAREBAZAAR_API_KEY", "")
    try:
        info = service.get_info(api_key, sha256_hash)
        return service.parse_enrichment(info) if info else {}
    except Exception:  # noqa: BLE001
        return {}


def _persist_live_enrichment(sha256_hash: str, live: dict) -> None:
    """실시간 보완 결과를 DB에 캐싱해 다음 조회부터는 즉시 응답되게 한다.

    enriched_at을 채우는 순간 get_sample_detail()의 분기가 'DB 우선' 경로를
    타게 되므로, 같은 해시를 다시 조회할 때는 더 이상 실시간 API를 부르지 않는다.
    """
    if not live:
        return
    vendor_score = live.get("vendor_score")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE samples SET
                    imphash = COALESCE(NULLIF(%s, ''), imphash),
                    tlsh = COALESCE(NULLIF(%s, ''), tlsh),
                    ssdeep = COALESCE(NULLIF(%s, ''), ssdeep),
                    reporter = COALESCE(NULLIF(%s, ''), reporter),
                    vendor_family = COALESCE(NULLIF(%s, ''), vendor_family),
                    vendor_score = COALESCE(%s::INTEGER, vendor_score),
                    enriched_at = NOW()
                WHERE sha256_hash = %s
            """, (
                live.get("imphash") or "", live.get("tlsh") or "", live.get("ssdeep") or "",
                live.get("reporter") or "", live.get("vendor_family") or "",
                vendor_score if vendor_score not in (None, "") else None,
                sha256_hash,
            ))

            yara_names = live.get("yara_rule_names") or []
            if yara_names:
                execute_values(
                    cur, "INSERT INTO yara_matches (sha256_hash, rule_name) VALUES %s",
                    [(sha256_hash, name) for name in yara_names],
                )

            behaviors = live.get("behaviors") or []
            if behaviors:
                execute_values(
                    cur, "INSERT INTO sample_behaviors (sha256_hash, behavior, score) VALUES %s",
                    [
                        (sha256_hash, b["behavior"], int(b["score"]) if b.get("score") not in (None, "") else None)
                        for b in behaviors
                    ],
                )

            references = live.get("references") or []
            if references:
                execute_values(
                    cur, "INSERT INTO sample_references (sha256_hash, context, value) VALUES %s",
                    [(sha256_hash, r.get("context") or None, r["value"]) for r in references],
                )
        conn.commit()
    except Exception:  # noqa: BLE001
        conn.rollback()
    finally:
        conn.close()


def get_sample_detail(sha256_hash: str) -> dict:
    sha256_hash = sha256_hash.lower()
    rows = _query("SELECT * FROM samples WHERE sha256_hash = %s", (sha256_hash,))
    if not rows:
        return {}
    sample = rows[0]
    sample["attack_mapping"] = _query(
        "SELECT software_name, technique_id, technique_name, tactic "
        "FROM attack_ttp_mapping WHERE signature = %s", (sample.get("signature"),)
    )

    if sample.get("enriched_at"):
        sample["yara_matches"] = _query(
            "SELECT rule_name FROM yara_matches WHERE sha256_hash = %s", (sha256_hash,)
        )
        sample["behaviors"] = _query(
            "SELECT behavior, score FROM sample_behaviors WHERE sha256_hash = %s "
            "ORDER BY score DESC NULLS LAST", (sha256_hash,)
        )
        sample["references"] = _query(
            "SELECT context, value FROM sample_references WHERE sha256_hash = %s", (sha256_hash,)
        )
        sample["live_enriched"] = False
    else:
        live = _live_enrich(sha256_hash)
        _persist_live_enrichment(sha256_hash, live)
        sample["yara_matches"] = [{"rule_name": n} for n in live.get("yara_rule_names", [])]
        sample["behaviors"] = live.get("behaviors", [])
        sample["references"] = live.get("references", [])
        sample["imphash"] = live.get("imphash") or sample.get("imphash")
        sample["tlsh"] = live.get("tlsh") or sample.get("tlsh")
        sample["ssdeep"] = live.get("ssdeep") or sample.get("ssdeep")
        sample["reporter"] = live.get("reporter") or sample.get("reporter")
        sample["vendor_family"] = live.get("vendor_family") or sample.get("vendor_family")
        sample["vendor_score"] = live.get("vendor_score") or sample.get("vendor_score")
        sample["live_enriched"] = bool(live)

    return sample


def get_attack_mapping_rate() -> dict:
    rows = _query("""
        SELECT
            (SELECT COUNT(DISTINCT signature) FROM samples WHERE signature <> 'unclassified') AS total_signatures,
            (SELECT COUNT(DISTINCT signature) FROM attack_ttp_mapping) AS matched_signatures
    """)
    row = rows[0] if rows else {"total_signatures": 0, "matched_signatures": 0}
    total = row["total_signatures"] or 0
    matched = row["matched_signatures"] or 0
    row["match_rate"] = round(matched / total * 100, 1) if total else 0.0
    return row


def get_top_techniques(n: int = 10) -> list:
    return _query("""
        SELECT technique_id, technique_name, COUNT(DISTINCT signature) AS signature_count
        FROM attack_ttp_mapping
        GROUP BY technique_id, technique_name
        ORDER BY signature_count DESC
        LIMIT %s
    """, (n,))


def get_attack_matrix() -> list:
    """Tactic x Technique 히트맵용 집계."""
    return _query("""
        SELECT tactic, technique_id, technique_name, COUNT(DISTINCT signature) AS count
        FROM attack_ttp_mapping
        WHERE tactic <> ''
        GROUP BY tactic, technique_id, technique_name
        ORDER BY tactic, count DESC
    """)


def get_available_groups() -> list:
    """드롭다운에 보여줄, MITRE Group 매칭에 성공한 로컬 APT 태그 목록."""
    return _query("""
        SELECT gtr.local_tag, gtr.mitre_group_name,
               (SELECT COUNT(*) FROM samples s WHERE gtr.local_tag = ANY(s.tags)) AS sample_count
        FROM group_tag_resolution gtr
        WHERE gtr.mitre_group_name IS NOT NULL AND gtr.mitre_group_name <> ''
        ORDER BY sample_count DESC
    """)


def _kill_chain_sort_key(tactic: str) -> int:
    try:
        return KILL_CHAIN_ORDER.index(tactic)
    except ValueError:
        return len(KILL_CHAIN_ORDER)


def get_group_attack_chain(local_tag: str) -> dict:
    """local_tag(예: 'Lazarus')로 태깅된 샘플을 근거로, 그 그룹의 MITRE 공식 attack
    chain(intrusion-set --uses--> technique/software) 중 어떤 technique이 우리
    데이터로도 뒷받침되는지 표시한다."""
    rows = _query(
        "SELECT mitre_group_name FROM group_tag_resolution WHERE local_tag = %s", (local_tag,)
    )
    group_name = rows[0]["mitre_group_name"] if rows else ""
    if not group_name:
        return {}

    chain_rows = _query("""
        SELECT technique_id, technique_name, tactic, via_software
        FROM attack_group_technique
        WHERE group_name = %s AND tactic <> ''
    """, (group_name,))

    local_technique_ids = {
        r["technique_id"] for r in _query("""
            SELECT DISTINCT m.technique_id
            FROM attack_ttp_mapping m
            WHERE m.signature IN (
                SELECT DISTINCT signature FROM samples WHERE %s = ANY(tags)
            )
        """, (local_tag,))
    }

    tactics = {}
    seen_techniques = set()
    for row in chain_rows:
        key = (row["technique_id"], row["tactic"])
        if key in seen_techniques:
            continue
        seen_techniques.add(key)
        tactics.setdefault(row["tactic"], []).append({
            "technique_id": row["technique_id"],
            "technique_name": row["technique_name"],
            "via_software": row["via_software"] or "",
            "observed_locally": row["technique_id"] in local_technique_ids,
        })

    ordered_tactics = [
        {"tactic": tactic, "techniques": techniques}
        for tactic, techniques in sorted(tactics.items(), key=lambda kv: _kill_chain_sort_key(kv[0]))
    ]

    return {
        "local_tag": local_tag,
        "group_name": group_name,
        "tactics": ordered_tactics,
        "local_technique_count": len(local_technique_ids),
        "total_technique_count": len(seen_techniques),
    }


def get_driver_category_distribution() -> list:
    return _query("""
        SELECT COALESCE(NULLIF(category, ''), 'unknown') AS category, COUNT(*) AS count
        FROM vulnerable_drivers
        GROUP BY category
    """)


def search_samples(query: str, limit: int = 20) -> list:
    like = f"%{query.lower()}%"
    return _query("""
        SELECT sha256_hash, file_name, signature, first_seen
        FROM samples
        WHERE LOWER(sha256_hash) LIKE %s OR LOWER(signature) LIKE %s OR LOWER(file_name) LIKE %s
        ORDER BY first_seen DESC
        LIMIT %s
    """, (like, like, like, limit))
