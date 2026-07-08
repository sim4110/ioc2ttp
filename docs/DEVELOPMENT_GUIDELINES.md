# 개발 Ground Rule

이 문서는 지금까지 이 프로젝트(`collectors/`, `processing/`, `app/`, `templates/`,
`static/`)에서 실제로 써온 코드 스타일을 정리한 것입니다. 새 코드를 추가하거나
기존 코드를 고칠 때는 아래 패턴을 따릅니다. Git 작업 규칙은 `docs/CLAUDE.md`를
따로 참고하세요.

## 0. 전체 원칙

- **정적 IoC 프로토타입 범위를 지킨다.** project.pdf가 정의한 범위(정적 공개
  데이터 수집·정제·시각화)를 벗어나는 기능(실시간 탐지, 인증/권한, 프로덕션
  하드닝 등)은 사용자가 명시적으로 요청하기 전까지 추가하지 않는다.
- **보고서(project.pdf)와의 추적성을 유지한다.** 모듈/함수가 보고서의 특정
  장·절을 구현한 것이면 docstring에 절 번호를 남긴다.
  ```python
  """데이터 전처리 (project.pdf 3-1, 3-2)."""
  ```
- **주석은 "왜"만 남긴다.** 코드가 무엇을 하는지는 함수/변수명으로 드러나야
  한다. 주석은 API의 비직관적인 동작, 설계 결정의 이유, 나중에 헷갈릴 만한
  트레이드오프를 설명할 때만 쓴다. (예: "get_recent/get_taginfo 목록 응답에는
  yara_rules가 없으므로 get_info로 개별 보강한다")
- **주석/문서는 한국어, 식별자는 영어.** 함수명·변수명·클래스명은 영어
  snake_case(Python)/camelCase(JS)로 쓰고, docstring과 주석은 한국어로 쓴다.

## 1. 파이프라인 구조: collect → preprocess → load

데이터가 흐르는 3단계를 절대 섞지 않는다. 각 단계는 독립적으로 재실행 가능해야
한다 (`python run_pipeline.py {collect|preprocess|load|all}`).

1. **`collectors/*.py`** — 외부 소스(API, GitHub raw 파일)에서 원본을 받아
   `data/raw/*.csv`에 그대로 쓴다. 여기서는 데이터를 다듬지 않는다(정규화 X).
   - 파일당 데이터 소스 하나. 공개 함수는 `collect(output_path, ...) -> int`
     (저장한 행 수 반환) 하나로 통일한다.
   - 모든 collector는 `if __name__ == "__main__":` 블록으로 단독 실행 가능해야
     한다.
   - 여러 값을 가진 필드(태그, 룰 이름 등)는 세미콜론(`;`)으로 join한 문자열로
     CSV에 저장한다. 세미콜론 안에 또 하위 필드가 필요하면(예: `behavior::score`)
     `::` 같은 별도 구분자를 쓴다.
   - 외부 API 호출은 개별 실패를 전체 실패로 번지게 하지 않는다 — 각 호출을
     `try/except Exception as exc: # noqa: BLE001`로 감싸고 로그만 남긴 뒤
     계속 진행한다 (배치 수집기의 회복력이 정확성보다 우선).
   - 진행 상황은 `print(f"[collector_name] ...")` 형식으로 남긴다 (로깅
     프레임워크 대신 print를 씀 — 이 프로젝트 규모에 맞게 단순하게 유지).

2. **`processing/preprocess.py`** — `data/raw/*.csv` → `data/processed/*.csv`.
   결측치 처리, 해시 소문자 정규화, 날짜 ISO 8601 통일, 리스트형 필드를
   자식 테이블용 행으로 펼치는 작업이 여기서 일어난다.
   - 정규화 헬퍼(`normalize_key`, `normalize_hash`, `normalize_datetime`)는
     이 파일 상단에 모아두고 다른 곳에서 재구현하지 않는다.
   - 각 처리 함수(`process_samples`, `process_drivers`, `process_attack_mapping`,
     `process_group_mapping`)는 입력 CSV 읽기 → dict 리스트 변환 → 출력 CSV
     쓰기 순서를 따르고, 끝에 `print(f"[preprocess] ...")`로 결과 건수/비율을
     요약한다. 이 요약 로그는 나중에 디버깅할 때 "왜 매칭이 안 됐지" 같은
     질문에 바로 답할 수 있어야 하므로 생략하지 않는다.
   - `run()` 함수가 전체 순서를 정의하고, 파일은 `if __name__ == "__main__":
     run()`로 끝난다.

3. **`processing/schema.sql` + `processing/db_loader.py`** —
   `data/processed/*.csv` → PostgreSQL.
   - 스키마는 `CREATE TABLE IF NOT EXISTS` + 이미 존재하는 환경을 위한
     `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` 마이그레이션으로 멱등성을
     보장한다.
   - 적재는 **full-refresh 방식**이다: 매 실행마다 관련 테이블을 FK 순서에
     맞게 `TRUNCATE ... RESTART IDENTITY CASCADE`한 뒤 전량 재적재한다
     (증분 upsert 아님). PK가 있는 테이블(`samples`, `vulnerable_drivers`)은
     추가로 `ON CONFLICT (pk) DO NOTHING`을 걸어 방어적으로 둔다.
   - 벌크 insert는 `psycopg2.extras.execute_values`만 쓴다 (행 단위 루프
     insert 금지).
   - 적재 함수 하나가 테이블 하나를 담당한다 (`load_samples`,
     `load_yara_matches`, ...). `run()`이 스키마 보장 → TRUNCATE → 적재
     순서로 전부 호출하고 마지막에 `conn.commit()`.

## 2. 백엔드 (`app/`)

- **계층 분리**: `service.py`(외부 API 클라이언트) → `model.py`(DB 쿼리,
  집계) → `api.py`(얇은 Flask 라우트) → `app.py`(앱 팩토리). 라우트 함수에
  SQL이나 비즈니스 로직을 직접 넣지 않는다.
- **DB 접근은 raw psycopg2**, ORM을 쓰지 않는다. 조회 함수는
  `RealDictCursor`로 JSON 직렬화 가능한 `dict`/`list[dict]`를 바로 반환한다.
  커넥션은 함수 안에서 열고 `finally: conn.close()`로 반드시 닫는다 (커넥션
  풀 없음 — 프로토타입 규모에 맞는 단순함 우선).
- **API 라우트 패턴**:
  ```python
  @api_bp.route("/dashboard/top-signatures")
  def top_signatures():
      n = request.args.get("n", default=10, type=int)
      return _handle(model.get_top_signatures, n)
  ```
  대부분의 GET 엔드포인트는 `_handle(model_fn, *args)` 한 줄로 끝난다.
  "없으면 404"가 의미 있는 리소스(샘플 상세, 그룹 조회)만 `if not result:
  return jsonify({"error": ...}), 404` 패턴으로 직접 분기한다.
- **환경설정**은 `python-dotenv` + `os.getenv("VAR", "기본값")`으로 읽는다.
  새 환경변수를 추가하면 `.env`에도 주석과 함께 추가한다.
- **외부 API 호출 로직을 두 곳에서 중복 구현하지 않는다.** 배치 수집기와
  API의 실시간 보완 경로가 같은 파싱이 필요하면(예: get_info 응답 해석)
  `app/service.py`에 공용 함수(`parse_enrichment` 같은)로 뽑아 양쪽에서
  재사용한다.

## 3. 프론트엔드 (`templates/`, `static/`)

- **빌드 스텝 없음.** Vue 3, Chart.js, Bootstrap 5는 전부 CDN `<script>`
  태그로 로드한다. npm/webpack을 도입하지 않는다.
- **Vue는 Options API**(`data()`, `computed`, `watch`, `methods`)를 쓰고
  Composition API를 섞지 않는다.
- **Jinja2 템플릿과 Vue mustache 문법이 겹치므로**, Vue가 렌더링하는
  `<div id="app">` 내부 전체를 `{% raw %}...{% endraw %}`로 감싼다. `url_for`가
  필요한 부분(정적 파일 경로)만 raw 블록 밖에 둔다.
- **API 호출**은 `fetchJSON(url)` 헬퍼 하나로 통일하고, 실패는
  `try/catch { console.error(e) }`로 조용히 삼킨다 (대시보드 위젯 하나가
  실패해도 나머지가 죽지 않도록).
- **Chart.js 인스턴스**는 `this._charts[id]`에 등록해두고, 다시 그리기 전에
  `destroy()`부터 호출한다 (탭 전환 시 캔버스가 재마운트되며 중복 생성되는
  것을 막기 위함).
- **도넛/파이 차트에는 `scales` 옵션을 주지 않는다** (`noScaleOptions()`
  사용) — cartesian 축이 없는 차트에 축 옵션을 주면 깨진다.
- **디자인 시스템은 Bootstrap 5 dark theme**(`data-bs-theme="dark"`)를
  기본으로 쓰고, `static/css/style.css`에는 Bootstrap에 없는 것(모노스페이스
  해시, kill-chain swimlane, 히트맵 셀 배경색 계산)만 최소한으로 추가한다.

## 4. 데이터 신뢰성 관련 관례

- **매칭/필터링 로직에는 항상 "몇 건 중 몇 건 매칭됐는지" 로그를 남긴다.**
  이 프로젝트에서 실제로 여러 번 버그(Heodo 누락, APT 태그 미수집)를 이
  로그 덕분에 잡았다. 조용히 매칭 실패하는 코드를 작성하지 않는다.
- **외부 소스 하나의 구조화 데이터가 부실할 수 있다는 것을 전제한다**
  (MITRE `x_mitre_aliases` 누락 사례). 매칭률이 낮으면 먼저 "다른 방법으로
  같은 것을 표현하는 별도 소스가 있는가"를 찾아본다 (MISP Galaxy 사례).
- **정규화 함수는 한 곳(`preprocess.py`)에만 정의**하고 다른 모듈에서
  import해서 쓴다. 같은 정규화 로직을 두 번 짜지 않는다.
