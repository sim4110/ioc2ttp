"""전체 파이프라인 실행기.

사용법:
    python run_pipeline.py collect     # 원본 데이터 수집 (data/raw)
    python run_pipeline.py preprocess  # 정제 (data/processed)
    python run_pipeline.py load        # PostgreSQL 적재
    python run_pipeline.py all         # 위 세 단계를 순서대로 실행
"""
import os
import sys

BASE_DIR = os.path.dirname(__file__)
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")


def step_collect():
    from collectors import (
        loldrivers_collector,
        malpedia_alias_collector,
        malwarebazaar_collector,
        mitre_attack_collector,
    )

    malwarebazaar_collector.collect(os.path.join(RAW_DIR, "malwarebazaar_samples.csv"))
    loldrivers_collector.collect(os.path.join(RAW_DIR, "loldrivers_samples.csv"))
    mitre_attack_collector.collect(
        output_path=os.path.join(RAW_DIR, "attack_software_technique.csv"),
        group_output_path=os.path.join(RAW_DIR, "attack_group_technique.csv"),
        cache_path=os.path.join(RAW_DIR, "enterprise-attack.json"),
    )
    malpedia_alias_collector.collect(os.path.join(RAW_DIR, "malpedia_aliases.csv"))


def step_preprocess():
    from processing import preprocess
    preprocess.run()


def step_load():
    from processing import db_loader
    db_loader.run()


STEPS = {
    "collect": step_collect,
    "preprocess": step_preprocess,
    "load": step_load,
}


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "all"
    if target == "all":
        for name, fn in STEPS.items():
            print(f"\n=== STEP: {name} ===")
            fn()
    elif target in STEPS:
        STEPS[target]()
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
