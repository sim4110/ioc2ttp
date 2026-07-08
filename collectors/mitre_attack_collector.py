"""MITRE ATT&CK STIX 데이터 수집기.

mitre-attack/attack-stix-data 저장소의 enterprise-attack.json(STIX 2.1 bundle)을
받아 두 종류의 관계를 CSV로 변환한다.

1. malware/tool --uses--> attack-pattern (표 3, project.pdf 2-2)
   -> attack_software_technique.csv
2. intrusion-set(Group) --uses--> attack-pattern 또는 malware/tool
   -> attack_group_technique.csv (그룹의 attack chain 분석용)
   그룹이 소프트웨어를 경유해 쓰는 technique은 via_software에 그 소프트웨어명을 남긴다.
"""
import csv
import json
import os

import requests

STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

SOFTWARE_FIELDNAMES = ["software_name", "aliases", "technique_id", "technique_name", "tactic"]
GROUP_FIELDNAMES = ["group_name", "aliases", "technique_id", "technique_name", "tactic", "via_software"]


def _download_bundle(cache_path: str) -> dict:
    if os.path.exists(cache_path):
        print(f"[mitre_attack] using cached bundle -> {cache_path}")
        with open(cache_path, "r", encoding="utf-8") as f:
            return json.load(f)

    print("[mitre_attack] downloading enterprise-attack.json (STIX bundle, 크기가 큽니다)...")
    resp = requests.get(STIX_URL, timeout=180)
    resp.raise_for_status()
    bundle = resp.json()

    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f)
    return bundle


def _parse_objects(objects: list):
    software_by_id = {}    # id -> {name, aliases}
    technique_by_id = {}   # id -> {technique_id, technique_name, tactics: [..]}
    group_by_id = {}       # id -> {name, aliases}
    relationships = []     # (source_ref, target_ref)

    for obj in objects:
        obj_type = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        if obj_type in ("malware", "tool"):
            software_by_id[obj["id"]] = {
                "name": obj.get("name", ""),
                "aliases": ";".join(obj.get("x_mitre_aliases") or []),
            }
        elif obj_type == "attack-pattern":
            ext_id = ""
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = ref.get("external_id", "")
                    break
            tactics = [
                phase.get("phase_name", "")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ]
            technique_by_id[obj["id"]] = {
                "technique_id": ext_id,
                "technique_name": obj.get("name", ""),
                "tactics": tactics or [""],
            }
        elif obj_type == "intrusion-set":
            # intrusion-set은 x_mitre_aliases가 아니라 STIX 표준 필드 aliases를 쓴다.
            group_by_id[obj["id"]] = {
                "name": obj.get("name", ""),
                "aliases": ";".join(obj.get("aliases") or []),
            }
        elif obj_type == "relationship" and obj.get("relationship_type") == "uses":
            relationships.append((obj.get("source_ref", ""), obj.get("target_ref", "")))

    return software_by_id, technique_by_id, group_by_id, relationships


def _build_software_technique_rows(software_by_id, technique_by_id, relationships):
    rows = []
    techniques_by_software_id = {}  # software_id -> [(technique_id, technique_name, tactic), ...]

    for source_ref, target_ref in relationships:
        software = software_by_id.get(source_ref)
        technique = technique_by_id.get(target_ref)
        if not software or not technique:
            continue
        for tactic in technique["tactics"]:
            rows.append({
                "software_name": software["name"],
                "aliases": software["aliases"],
                "technique_id": technique["technique_id"],
                "technique_name": technique["technique_name"],
                "tactic": tactic,
            })
            techniques_by_software_id.setdefault(source_ref, []).append(
                (technique["technique_id"], technique["technique_name"], tactic)
            )

    return rows, techniques_by_software_id


def _build_group_technique_rows(group_by_id, software_by_id, technique_by_id, relationships, techniques_by_software_id):
    seen = set()
    rows = []

    for source_ref, target_ref in relationships:
        group = group_by_id.get(source_ref)
        if not group:
            continue

        # 그룹이 technique을 직접 쓰는 경우
        technique = technique_by_id.get(target_ref)
        if technique:
            for tactic in technique["tactics"]:
                key = (group["name"], technique["technique_id"], tactic, "")
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "group_name": group["name"], "aliases": group["aliases"],
                    "technique_id": technique["technique_id"], "technique_name": technique["technique_name"],
                    "tactic": tactic, "via_software": "",
                })
            continue

        # 그룹이 소프트웨어를 쓰고, 그 소프트웨어가 technique을 쓰는 경우 (간접)
        software = software_by_id.get(target_ref)
        if software:
            for technique_id, technique_name, tactic in techniques_by_software_id.get(target_ref, []):
                key = (group["name"], technique_id, tactic, software["name"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append({
                    "group_name": group["name"], "aliases": group["aliases"],
                    "technique_id": technique_id, "technique_name": technique_name,
                    "tactic": tactic, "via_software": software["name"],
                })

    return rows


def _write_csv(path: str, fieldnames: list, rows: list) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def collect(output_path: str, group_output_path: str, cache_path: str) -> tuple:
    bundle = _download_bundle(cache_path)
    objects = bundle.get("objects", [])

    software_by_id, technique_by_id, group_by_id, relationships = _parse_objects(objects)

    software_rows, techniques_by_software_id = _build_software_technique_rows(
        software_by_id, technique_by_id, relationships
    )
    group_rows = _build_group_technique_rows(
        group_by_id, software_by_id, technique_by_id, relationships, techniques_by_software_id
    )

    _write_csv(output_path, SOFTWARE_FIELDNAMES, software_rows)
    _write_csv(group_output_path, GROUP_FIELDNAMES, group_rows)

    print(f"[mitre_attack] saved {len(software_rows)} software-technique rows -> {output_path}")
    print(f"[mitre_attack] saved {len(group_rows)} group-technique rows ({len(group_by_id)} groups) -> {group_output_path}")
    return len(software_rows), len(group_rows)


if __name__ == "__main__":
    base = os.path.join(os.path.dirname(__file__), "..", "data")
    collect(
        output_path=os.path.join(base, "raw", "attack_software_technique.csv"),
        group_output_path=os.path.join(base, "raw", "attack_group_technique.csv"),
        cache_path=os.path.join(base, "raw", "enterprise-attack.json"),
    )
