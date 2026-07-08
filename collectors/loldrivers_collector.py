"""LOLDrivers 데이터 수집기.

https://www.loldrivers.io/api/drivers.json 을 받아 표 2(project.pdf 2-2)에
정의된 필드로 CSV를 저장한다. 드라이버 하나가 여러 KnownVulnerableSamples를
가질 수 있으므로 샘플 단위로 행을 펼친다(flatten).
"""
import csv
import os
import re

import requests

DRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

FIELDNAMES = [
    "driver_sha256", "driver_md5", "driver_sha1",
    "filename", "publisher", "company", "category", "tags", "cve_id",
]


def _extract_cve(driver: dict) -> str:
    text_parts = [driver.get("Description") or ""]
    for res in driver.get("Resources") or []:
        if isinstance(res, str):
            text_parts.append(res)
    text = " ".join(text_parts)
    match = CVE_PATTERN.search(text)
    return match.group(0).upper() if match else ""


def collect(output_path: str) -> int:
    print("[loldrivers] downloading drivers.json ...")
    resp = requests.get(DRIVERS_URL, timeout=60)
    resp.raise_for_status()
    drivers = resp.json()

    rows = []
    for driver in drivers:
        category = driver.get("Category", "")
        tags = ";".join(driver.get("Tags") or [])
        cve_id = _extract_cve(driver)

        for sample in driver.get("KnownVulnerableSamples") or []:
            signature = sample.get("Signature") or {}
            # Signature는 리스트/딕셔너리 형태가 혼재할 수 있어 방어적으로 처리
            if isinstance(signature, list):
                signature = signature[0] if signature else {}

            rows.append({
                "driver_sha256": (sample.get("SHA256") or "").lower(),
                "driver_md5": (sample.get("MD5") or "").lower(),
                "driver_sha1": (sample.get("SHA1") or "").lower(),
                "filename": sample.get("Filename", ""),
                "publisher": signature.get("Publisher", "") if isinstance(signature, dict) else "",
                "company": sample.get("Company", ""),
                "category": category,
                "tags": tags,
                "cve_id": cve_id,
            })

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[loldrivers] saved {len(rows)} rows -> {output_path}")
    return len(rows)


if __name__ == "__main__":
    collect(os.path.join(os.path.dirname(__file__), "..", "data", "raw", "loldrivers_samples.csv"))
