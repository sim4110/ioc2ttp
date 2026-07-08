# 정적 IoC 기반 시각화 대시보드 및 공격체인 분석 웹서비스 (프로토타입)

`project.pdf` 설계를 바탕으로 한 엔드투엔드 프로토타입입니다.

MalwareBazaar / LOLDrivers / MITRE ATT&CK 데이터를 수집·전처리해 PostgreSQL에 적재하고,
Flask REST API + Vue.js(CDN) + Chart.js로 시각화합니다.

## 아키텍처

```
MalwareBazaar API ─┐
LOLDrivers GitHub ─┼─> collectors/*.py ─> data/raw/*.csv
MITRE ATT&CK STIX ─┤
MISP Galaxy(Malpedia)┘  (ATT&CK 별칭 보강용 크로스워크)
                         │
                         ▼
                processing/preprocess.py ─> data/processed/*.csv
                         │
                         ▼
                processing/db_loader.py ─> PostgreSQL (Docker)
                         │
                         ▼
                app/ (Flask REST API) ─> templates/index.html (Vue.js + Chart.js)
```

## 준비

```bash
python -m venv venv
source venv/Scripts/activate   # Windows Git Bash
pip install -r requirements.txt
```

`.env` 파일에 MalwareBazaar API 키(https://bazaar.abuse.ch/account/ 에서 발급)와
DB 접속 정보를 입력합니다 (docker-compose.yml 기본값과 이미 맞춰져 있음).

## DB 실행 (Docker)

```bash
docker compose up -d
```

## 파이프라인 실행

```bash
python run_pipeline.py collect     # MalwareBazaar/LOLDrivers/MITRE ATT&CK 원본 수집
python run_pipeline.py preprocess  # 정제 (결측치, 해시 정규화, CVE 파싱, ATT&CK 키 매칭 등)
python run_pipeline.py load        # PostgreSQL 적재 (매 실행마다 전체 갱신)
# 또는 한 번에: python run_pipeline.py all
```

MITRE ATT&CK STIX 번들은 `data/raw/enterprise-attack.json`에 캐시되어, 두 번째 실행부터는
재다운로드하지 않습니다.

## 웹서비스 실행

```bash
python -m app.app
```

브라우저에서 http://localhost:5000 접속. 페이지 구성은 project.pdf 5-2와 동일합니다.

- **메인 대시보드**: Top N 패밀리/YARA 룰, 시계열 추이, 파일 유형 분포, 드라이버 카테고리 분포
- **샘플 상세 조회**: 해시/패밀리명/파일명 검색 → 메타데이터, YARA 매칭 근거, ATT&CK 매핑
- **ATT&CK 매핑 탭**: 매핑률, Top N Technique, Tactic × Technique 히트맵, 그룹별 Attack Chain
- **Footer**: 총 수집 건수, 수집 기간, 출처

## 그룹별 Attack Chain (APT Group 단위 분석)

기존 매핑(signature → software → technique)은 "어떤 technique이 전체적으로 많이 쓰였는가"만
보여줄 뿐, 특정 위협 행위자의 공격 흐름은 알 수 없었다. 이를 위해 MITRE STIX의
`intrusion-set`(Group) 객체와 그 `uses` 관계(Group→Technique 직접, Group→Software→Technique
간접)를 `collectors/mitre_attack_collector.py`에서 추가로 추출해
`attack_group_technique` 테이블에 저장한다.

우리가 MalwareBazaar에서 수집에 사용한 APT 태그(`Lazarus`, `APT29`, `Kimsuky` 등
10개, `collectors/malwarebazaar_collector.py`의 `APT_TAGS`)는 `processing/preprocess.py`의
`_resolve_group_for_tag()`가 MITRE Group 정식명/별칭과 대조해 매핑한다
(예: `OceanLotus` → `APT32`, `APT34` → `OilRig`). 10개 태그 전부 매칭 성공했다.

ATT&CK 매핑 탭에서 그룹을 선택하면(`GET /api/attack/group/<local_tag>`):
- MITRE가 공식 문서화한 해당 그룹의 전체 attack chain을 kill chain 순서
  (reconnaissance → ... → impact)대로 보여주고,
- 그중 어떤 technique이 **우리가 실제로 수집한 해당 그룹 태그 샘플**로도
  뒷받침되는지(`observed_locally`) 빨간 배지로 구분한다.

즉 "MITRE 문서상의 이론적 attack chain"과 "우리 정적 IoC 데이터로 검증 가능한 부분"을
한 화면에서 대조해서 볼 수 있다.

참고로 이 STIX 데이터에서 MITRE가 기존 `defense-evasion` 단일 tactic을 `stealth`와
`defense-impairment`로 세분화한 것을 확인했다 — `app/model.py`의 `KILL_CHAIN_ORDER`가
이를 반영해 정렬한다.

## ATT&CK 매칭 보강 (Malpedia 별칭 크로스워크)

MITRE ATT&CK의 `x_mitre_aliases`는 구조화된 별칭이 부실하다 (예: Emotet에 흔히 쓰이는
별칭 `Heodo`, `Geodo` 중 `Geodo`만 등록되어 있고 `Heodo`는 누락). 이를 보완하기 위해
[MISP Galaxy](https://github.com/MISP/misp-galaxy)가 배포하는 Malpedia 클러스터
(`clusters/malpedia.json`, 3,683개 패밀리·synonyms 포함)를 별도 수집원으로 추가했다.

`processing/preprocess.py`의 `build_alias_clusters()`가 이 데이터를 정규화된 이름 기준
동치 클래스(같은 패밀리로 취급되는 이름 집합)로 구성하고, `process_attack_mapping()`은
signature를 ATT&CK와 직접 매칭하기 전에 먼저 이 클러스터로 확장한 후보 이름들로도
매칭을 시도한다. 예: `Heodo` → (Malpedia 클러스터) → `{Emotet, Geodo, Heodo}` →
`Geodo`가 ATT&CK 룩업에 있으므로 매칭 성공.

이 보강 덕분에 현재 수집 데이터 기준 총 76개 signature 중 30개(약 39.5%)가 ATT&CK
매핑에 성공한다. 특히 `Heodo`처럼 MITRE `x_mitre_aliases`에는 없지만 Malpedia
클러스터로만 잡히는 별칭이 실제 샘플 규모가 큰 패밀리일수록 이 보강의 효과가 크다.

## 한계 (project.pdf 6장과 동일)

- MalwareBazaar 목록 조회(get_recent/get_taginfo) 응답에는 yara_rules가 없어, signature가
  있는 샘플 중 일부(`yara_enrich_limit`, 기본 300건)만 `get_info`로 개별 보강한다.
- signature ↔ ATT&CK 명칭 매칭은 (Malpedia 별칭 보강을 포함해도) 여전히 정적 이름 기준이며,
  ATT&CK가 아예 문서화하지 않은 커머디티 악성코드 패밀리는 매칭되지 않는다 (보고서 6장 참고).
