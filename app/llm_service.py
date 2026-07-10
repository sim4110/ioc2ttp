"""Claude API 클라이언트 — 샘플 상세 페이지의 'AI 분석' 기능 전용.

app/service.py(MalwareBazaar 클라이언트)와 동일하게 이 파일은 외부 API 호출
로직만 담당한다. 분석 대상 데이터 조립은 app/model.py, 라우팅은 app/api.py에 둔다.
"""
import json

import anthropic

MODEL_ID = "claude-sonnet-5"

# 악성코드 분석가가 트리아지 시 우선적으로 확인해야 할 항목을 고정된 JSON 스키마로
# 강제한다 — 화면 렌더링이 매번 같은 구조를 기대할 수 있어야 하므로 자유 텍스트로
# 받지 않는다.
#
# severity/핵심 지표/우선순위 technique 선정을 LLM의 자유 판단에 맡기면 같은 샘플을
# 다시 분석했을 때 등급·선정 결과가 실행마다 흔들릴 수 있다. 이를 막기 위해 판정
# 기준을 아래 룰북(ANALYST_RULEBOOK)으로 고정하고, 모델이 새로운 기준을 만들어내지
# 않고 이 룰만 근거로 판정하도록 강제한다 (완전한 결정론은 LLM 특성상 보장되지
# 않지만, 판정 기준 자체가 흔들리는 것은 이 방식으로 방지한다).
ANALYST_RULEBOOK = """[심각도(severity) 판정 룰 — 아래 조건만 근거로 판정하고, 어떤 룰이 적용됐는지는
severity_matched_rule 필드에만 룰 번호("SEV-1a" 등)로 남겨라]
SEV-1 (critical): 다음 중 하나라도 해당
  a) attack_mapping에 tactic이 'impact'인 technique이 하나라도 있다
  b) vendor_score가 80 이상이면서, behaviors에 credential-access 계열 행위(예: keylogging,
     credential dumping, password 관련)와 command-and-control/exfiltration 계열 행위(예: 네트워크
     비콘, clipboard 탈취)가 동시에 관찰된다
SEV-2 (high): SEV-1에 해당하지 않고, 다음 중 하나
  a) vendor_score가 70 이상이다
  b) attack_mapping에 credential-access, collection, command-and-control, exfiltration,
     lateral-movement 중 하나 이상의 tactic이 매핑되어 있고, behaviors 중 최소 1개가 그
     technique과 직접 연관된다
SEV-3 (medium): SEV-1/SEV-2에 해당하지 않고, YARA 매칭 또는 behaviors가 1개 이상 존재한다
SEV-4 (low): YARA 매칭도 behaviors도 attack_mapping도 없거나, signature가 'unclassified'다

[핵심 지표(key_indicators) 선정 룰]
IND-1: sha256_hash는 화면에 이미 표시되므로 중복 기재하지 않는다.
IND-2: imphash/ssdeep/tlsh 중 값이 존재하는 것을 우선 포함한다 (유사 샘플 클러스터링 근거).
IND-3: vendor_family가 존재하면 포함한다 (패밀리 귀속 근거).
IND-4: 위 조건으로 3개 미만이면 YARA 매칭 룰 이름으로 채운다.

[검증 우선순위 technique(priority_techniques) 선정 룰 — 최대 5개, 매핑된 전체를 나열하지 않는다]
TECH-1: behaviors와 직접 대응되는 technique을 최우선으로 한다.
TECH-2: tactic이 credential-access, collection, command-and-control, exfiltration, impact,
  lateral-movement인 technique을 그다음 우선순위로 한다.
TECH-3: 그 외 tactic(discovery, defense-impairment, stealth, persistence, execution 등)은
  TECH-1/TECH-2로 2개 미만이 선정됐을 때만 보충한다.
각 technique에 어떤 룰(TECH-1/2/3)이 적용됐는지는 matched_rule 필드에만 남겨라."""

# 리버싱 체크리스트 생성 룰. 우리는 실제 바이너리도, import/export 함수 목록도 갖고
# 있지 않다(정적 메타데이터뿐) — 그래서 이 항목들은 "이 샘플은 X 함수를 가진다"는
# 단정이 아니라, 분석가가 IDA/Ghidra/PE 뷰어 등으로 직접 열었을 때 "무엇을 확인해야
# 하는지"를 관찰된 행위/technique에 근거해 제안하는 형태여야 한다.
REVERSING_RULEBOOK = """[리버싱 체크리스트(reversing_checklist) 생성 룰 — 최소 5개, 최대 8개.
정적 메타데이터만으로는 실제 import/export 함수 목록을 알 수 없으므로, "이 샘플은 OO 함수를
가진다"처럼 단정하지 말고 "OO 함수가 있는지 확인하세요" 형태의 제안으로만 작성하라.]
REV-1 (Import Table 확인 API — behaviors에 아래 키워드가 있으면 대응 API를 후보로 제시):
  - keylog 계열 → GetAsyncKeyState, SetWindowsHookExA/W, GetKeyboardState
  - clipboard 계열 → OpenClipboard, GetClipboardData, SetClipboardData
  - screen capture/screenshot 계열 → BitBlt, GetDC, CreateCompatibleBitmap
  - process injection 계열 → CreateRemoteThread, WriteProcessMemory, VirtualAllocEx,
    NtUnmapViewOfSection
  - network/beacon/C2 계열 → InternetOpenA/W, WinHttpOpen, send/recv, URLDownloadToFileA
  - persistence 계열 → RegSetValueExA/W, CreateServiceA/W, 작업 스케줄러 관련 COM 인터페이스
  - credential 계열 → CryptUnprotectData, LsaEnumerateLogonSessions, advapi32 관련 API
REV-2 (tactic 기반 우선순위): attack_mapping에 credential-access, collection,
  command-and-control, exfiltration, impact tactic이 있으면 그와 연관된 import/문자열 확인을
  체크리스트 상위에 둔다.
REV-3 (패킹/난독화 우선 확인): yara_matches 룰 이름에 packer/crypter/protect/obfusc 등의
  키워드가 있으면 언패킹·디오퍼스케이션 확인 항목을 맨 앞에 둔다. 없어도 섹션 엔트로피/컴파일
  타임스탬프 위조 여부 확인 항목(PE_HEADER)은 항상 1개 포함한다.
REV-4 (export 함수 확인): file_type이 dll이면 EXPORT_TABLE 영역 항목을 포함하고, exe 등
  다른 타입이면 생략한다.
REV-5 (문자열/리소스는 항상 포함): STRINGS(C2 URL·뮤텍스명·하드코딩 크리덴셜 후보 검색)와
  RESOURCES(.rsrc의 추가 페이로드/설정 파일 임베딩 여부) 항목을 각각 최소 1개 포함한다.
각 항목의 area는 PE_HEADER/IMPORT_TABLE/EXPORT_TABLE/STRINGS/RESOURCES/ANTI_ANALYSIS/NETWORK
중 하나로 분류하고, 어떤 룰(REV-1~5)이 적용됐는지는 matched_rule 필드에만 남겨라."""

ANALYST_SYSTEM_PROMPT = f"""당신은 CTI(Cyber Threat Intelligence) 팀에서 악성코드 분석가의 트리아지와,
분석가가 실제 리버싱(정적/동적 분석)에 착수하기 전 무엇부터 확인해야 하는지를 가이드하는
어시스턴트다. 아래에 주어지는 것은 하나의 악성코드 샘플에 대해 정적으로 수집된 메타데이터
(해시, YARA 룰 매칭, 벤더 행위 태그, ATT&CK technique 매핑, 참고 링크)뿐이다. 샘플 바이너리
자체나 동적 실행 결과, import/export 함수 목록은 주어지지 않는다.

분석가가 이 샘플을 처음 볼 때 가장 먼저 무엇을 확인해야 하는지, 아래 룰북에 정의된
기준만 근거로 판정해 지정된 JSON 스키마에 맞춰 한국어로 답하라.

{ANALYST_RULEBOOK}

{REVERSING_RULEBOOK}

그 외 규칙:
- 주어진 데이터에 없는 해시, IOC, technique, import/export 함수를 사실인 것처럼 지어내지 마라.
- 근거가 빈약하거나 데이터 자체가 없는 항목은 data_gaps에 명시하라.
- 룰북에 없는 새로운 판정 기준을 스스로 만들어내지 마라. 애매하면 더 낮은/보수적인
  등급 쪽 룰을 적용하고 그 이유를 severity_reasoning에 남겨라.
- severity_reasoning, why_priority, reversing_checklist의 focus/why_relevant는 분석가가
  읽을 화면에 그대로 노출된다. "SEV-1b", "TECH-2", "REV-1" 같은 룰 번호나 룰북 용어를
  이 필드들에 절대 언급하지 말고, 왜 그런지를 분석가가 바로 이해할 수 있는 자연스러운
  문장으로 풀어써라. 룰 번호는 severity_matched_rule/matched_rule 필드에만 적어라.
- reversing_checklist의 focus/why_relevant는 확정된 사실이 아니라 제안이므로 "~한다"가
  아니라 "~확인하세요", "~있는지 살펴보세요"처럼 권유형으로 써라.
- behavior_highlights와 recommended_actions는 항목당 한 문장으로 간결하게 써라."""

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "threat_summary": {
            "type": "string",
            "description": "이 샘플이 무엇인지 2~3문장 요약",
        },
        "severity": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
        },
        # 화면에는 절대 렌더링하지 않는 감사(audit)용 필드 — 어떤 룰로 이 등급이
        # 나왔는지 로그/디버깅 목적으로만 남긴다.
        "severity_matched_rule": {
            "type": "string",
            "enum": ["SEV-1a", "SEV-1b", "SEV-2a", "SEV-2b", "SEV-3", "SEV-4"],
        },
        "severity_reasoning": {"type": "string"},
        "key_indicators": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "description": "예: imphash, ssdeep, yara_rule"},
                    "value": {"type": "string"},
                    "note": {"type": "string", "description": "분석가가 왜 이 지표를 봐야 하는지"},
                },
                "required": ["type", "value", "note"],
                "additionalProperties": False,
            },
        },
        "priority_techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "why_priority": {"type": "string"},
                    # 화면에 렌더링하지 않는 감사용 필드 (severity_matched_rule과 동일한 목적)
                    "matched_rule": {"type": "string", "enum": ["TECH-1", "TECH-2", "TECH-3"]},
                },
                "required": ["technique_id", "technique_name", "why_priority", "matched_rule"],
                "additionalProperties": False,
            },
        },
        "behavior_highlights": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "data_gaps": {"type": "array", "items": {"type": "string"}},
        "reversing_checklist": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "area": {
                        "type": "string",
                        "enum": [
                            "PE_HEADER", "IMPORT_TABLE", "EXPORT_TABLE", "STRINGS",
                            "RESOURCES", "ANTI_ANALYSIS", "NETWORK",
                        ],
                    },
                    "focus": {"type": "string", "description": "리버싱 도구에서 구체적으로 무엇을 확인할지"},
                    "why_relevant": {"type": "string", "description": "이 샘플의 어떤 데이터 때문에 우선순위가 됐는지"},
                    # 화면에 렌더링하지 않는 감사용 필드
                    "matched_rule": {
                        "type": "string",
                        "enum": ["REV-1", "REV-2", "REV-3", "REV-4", "REV-5"],
                    },
                },
                "required": ["area", "focus", "why_relevant", "matched_rule"],
                "additionalProperties": False,
            },
        },
    },
    "required": [
        "threat_summary", "severity", "severity_matched_rule", "severity_reasoning",
        "key_indicators", "priority_techniques", "behavior_highlights",
        "recommended_actions", "data_gaps", "reversing_checklist",
    ],
    "additionalProperties": False,
}


def _build_user_prompt(sample: dict) -> str:
    curated = {
        "sha256_hash": sample.get("sha256_hash"),
        "file_name": sample.get("file_name"),
        "file_type": sample.get("file_type"),
        "file_size": sample.get("file_size"),
        "signature": sample.get("signature"),
        "tags": sample.get("tags"),
        "first_seen": str(sample.get("first_seen") or ""),
        "delivery_method": sample.get("delivery_method"),
        "origin_country": sample.get("origin_country"),
        "code_sign": sample.get("code_sign"),
        "imphash": sample.get("imphash"),
        "tlsh": sample.get("tlsh"),
        "ssdeep": sample.get("ssdeep"),
        "vendor_family": sample.get("vendor_family"),
        "vendor_score": sample.get("vendor_score"),
        "yara_matches": [m.get("rule_name") for m in sample.get("yara_matches", [])],
        "behaviors": sample.get("behaviors", []),
        "attack_mapping": sample.get("attack_mapping", []),
        "references": (sample.get("references") or [])[:20],
    }
    return json.dumps(curated, ensure_ascii=False, indent=2, default=str)


def analyze_sample(sample: dict) -> dict:
    """샘플 메타데이터를 분석가 우선순위 요약(JSON)으로 변환한다.

    API 키 미설정, 요청 실패 등은 호출부(app/api.py)가 처리하도록 예외를 그대로 전달한다.
    """
    client = anthropic.Anthropic()
    response = client.messages.create(
        model=MODEL_ID,
        max_tokens=7000,
        # Claude Sonnet 5는 thinking을 명시하지 않으면 기본적으로 adaptive thinking이
        # 켜지고, max_tokens는 thinking+응답 텍스트를 합쳐서 소진된다. 룰북에 따른
        # 기계적 판정 작업이라 깊은 추론이 필요 없으므로 꺼서, JSON 응답이 thinking에
        # 밀려 잘리는 문제(json.loads의 "Unterminated string" 에러)를 막는다.
        thinking={"type": "disabled"},
        system=ANALYST_SYSTEM_PROMPT,
        output_config={"format": {"type": "json_schema", "schema": ANALYSIS_SCHEMA}},
        messages=[{"role": "user", "content": _build_user_prompt(sample)}],
    )
    if response.stop_reason == "max_tokens":
        raise RuntimeError("LLM 응답이 max_tokens 제한으로 잘렸습니다. 다시 시도해주세요.")
    text = next(block.text for block in response.content if block.type == "text")
    return json.loads(text)
