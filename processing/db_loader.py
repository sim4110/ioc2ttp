"""전처리된 CSV(data/processed)를 PostgreSQL에 적재한다.

배치 수집 설계(project.pdf 2-3)에 맞춰, 매 실행마다 전체 테이블을 비우고
새로 채우는 full-refresh 방식을 사용한다.
"""
import csv
import os

import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import execute_values

load_dotenv()

PROCESSED_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "cti_dashboard"),
        user=os.getenv("DB_USER", "cti_user"),
        password=os.getenv("DB_PASSWORD", "cti_password"),
    )


def _read_csv(name: str) -> list:
    path = os.path.join(PROCESSED_DIR, name)
    if not os.path.exists(path):
        return []
    with open(path, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def ensure_schema(cur):
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        cur.execute(f.read())


def load_samples(cur):
    rows = _read_csv("samples.csv")
    values = [
        (
            r["sha256_hash"], r["md5_hash"] or None, r["sha1_hash"] or None,
            r["file_name"] or None, int(r["file_size"]) if r["file_size"] else None,
            r["file_type"] or None, r["signature"] or None,
            [t for t in (r["tags"] or "").split(";") if t],
            r["first_seen"] or None, r["last_seen"] or None,
            r["delivery_method"] or None, r["origin_country"] or None,
            r["code_sign"] or None,
            r["imphash"] or None, r["tlsh"] or None, r["ssdeep"] or None,
            r["reporter"] or None, r["vendor_family"] or None,
            int(r["vendor_score"]) if r["vendor_score"] else None,
            r["enriched_at"] or None,
        )
        for r in rows
    ]
    if values:
        execute_values(
            cur,
            """INSERT INTO samples (sha256_hash, md5_hash, sha1_hash, file_name,
                file_size, file_type, signature, tags, first_seen, last_seen,
                delivery_method, origin_country, code_sign,
                imphash, tlsh, ssdeep, reporter, vendor_family, vendor_score, enriched_at)
               VALUES %s ON CONFLICT (sha256_hash) DO NOTHING""",
            values,
        )
    print(f"[db_loader] samples: {len(values)} rows")


def load_yara_matches(cur):
    rows = _read_csv("yara_matches.csv")
    values = [(r["sha256_hash"], r["rule_name"]) for r in rows]
    if values:
        execute_values(
            cur,
            "INSERT INTO yara_matches (sha256_hash, rule_name) VALUES %s",
            values,
        )
    print(f"[db_loader] yara_matches: {len(values)} rows")


def load_sample_behaviors(cur):
    rows = _read_csv("sample_behaviors.csv")
    values = [
        (r["sha256_hash"], r["behavior"], int(r["score"]) if r["score"] else None)
        for r in rows
    ]
    if values:
        execute_values(
            cur,
            "INSERT INTO sample_behaviors (sha256_hash, behavior, score) VALUES %s",
            values,
        )
    print(f"[db_loader] sample_behaviors: {len(values)} rows")


def load_sample_references(cur):
    rows = _read_csv("sample_references.csv")
    values = [(r["sha256_hash"], r["context"] or None, r["value"]) for r in rows]
    if values:
        execute_values(
            cur,
            "INSERT INTO sample_references (sha256_hash, context, value) VALUES %s",
            values,
        )
    print(f"[db_loader] sample_references: {len(values)} rows")


def load_vulnerable_drivers(cur):
    rows = _read_csv("vulnerable_drivers.csv")
    values = [
        (r["hash_sha256"], r["driver_name"] or None, r["category"] or None,
         r["cve_id"] or None, r["publisher"] or None, r["source"] or "loldrivers")
        for r in rows
    ]
    if values:
        execute_values(
            cur,
            """INSERT INTO vulnerable_drivers
                (hash_sha256, driver_name, category, cve_id, publisher, source)
               VALUES %s ON CONFLICT (hash_sha256) DO NOTHING""",
            values,
        )
    print(f"[db_loader] vulnerable_drivers: {len(values)} rows")


def load_attack_ttp_mapping(cur):
    rows = _read_csv("attack_ttp_mapping.csv")
    values = [
        (r["signature"], r["software_name"], r["technique_id"], r["technique_name"], r["tactic"])
        for r in rows
    ]
    if values:
        execute_values(
            cur,
            """INSERT INTO attack_ttp_mapping
                (signature, software_name, technique_id, technique_name, tactic)
               VALUES %s""",
            values,
        )
    print(f"[db_loader] attack_ttp_mapping: {len(values)} rows")


def load_attack_group_technique(cur):
    rows = _read_csv("attack_group_technique.csv")
    values = [
        (r["group_name"], r["technique_id"], r["technique_name"], r["tactic"], r["via_software"] or None)
        for r in rows
    ]
    if values:
        execute_values(
            cur,
            """INSERT INTO attack_group_technique
                (group_name, technique_id, technique_name, tactic, via_software)
               VALUES %s""",
            values,
        )
    print(f"[db_loader] attack_group_technique: {len(values)} rows")


def load_group_tag_resolution(cur):
    rows = _read_csv("group_tag_resolution.csv")
    values = [(r["local_tag"], r["mitre_group_name"] or None) for r in rows]
    if values:
        execute_values(
            cur,
            """INSERT INTO group_tag_resolution (local_tag, mitre_group_name)
               VALUES %s ON CONFLICT (local_tag) DO UPDATE SET mitre_group_name = EXCLUDED.mitre_group_name""",
            values,
        )
    print(f"[db_loader] group_tag_resolution: {len(values)} rows")


def run():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            ensure_schema(cur)
            cur.execute(
                "TRUNCATE TABLE yara_matches, sample_behaviors, sample_references, "
                "attack_ttp_mapping, attack_group_technique, vulnerable_drivers, samples RESTART IDENTITY CASCADE"
            )
            load_samples(cur)
            load_yara_matches(cur)
            load_sample_behaviors(cur)
            load_sample_references(cur)
            load_vulnerable_drivers(cur)
            load_attack_ttp_mapping(cur)
            load_attack_group_technique(cur)
            load_group_tag_resolution(cur)
        conn.commit()
        print("[db_loader] done.")
    finally:
        conn.close()


if __name__ == "__main__":
    run()
