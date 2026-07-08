"""악성코드 패밀리 별칭(alias) 크로스워크 수집기.

MITRE ATT&CK의 x_mitre_aliases 필드는 구조화된 별칭이 부실해서(예: Emotet에
'Heodo'가 빠져 있음), MalwareBazaar의 signature와 ATT&CK의 software 이름이
서로 다른 별칭을 쓰면 정규화 매칭만으로는 놓치는 경우가 많다.

MISP Galaxy 프로젝트가 배포하는 Malpedia 클러스터(clusters/malpedia.json)는
보안 벤더별 명칭 동의어를 폭넓게 모아둔 공개 데이터로, 이를 별도의 별칭
크로스워크 소스로 수집해 ATT&CK 매칭의 보조 지표로 사용한다.
"""
import csv
import os

import requests

MALPEDIA_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json"
FIELDNAMES = ["canonical_name", "alias_name"]


def collect(output_path: str) -> int:
    print("[malpedia_alias] downloading MISP Galaxy malpedia.json ...")
    resp = requests.get(MALPEDIA_URL, timeout=120)
    resp.raise_for_status()
    clusters = resp.json().get("values", [])

    rows = []
    for cluster in clusters:
        canonical = (cluster.get("value") or "").strip()
        if not canonical:
            continue
        rows.append({"canonical_name": canonical, "alias_name": canonical})
        for synonym in (cluster.get("meta") or {}).get("synonyms") or []:
            synonym = (synonym or "").strip()
            if synonym:
                rows.append({"canonical_name": canonical, "alias_name": synonym})

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[malpedia_alias] saved {len(rows)} rows ({len(clusters)} clusters) -> {output_path}")
    return len(rows)


if __name__ == "__main__":
    collect(os.path.join(os.path.dirname(__file__), "..", "data", "raw", "malpedia_aliases.csv"))
