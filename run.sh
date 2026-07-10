#!/usr/bin/env bash
# ============================================================================
# run.sh --- Oracle Linux 8 (OCI Compute VM) 배포/실행 스크립트
#
# 사용 예:
#   ./run.sh bootstrap    # (1회만) OS 패키지·Docker 설치, 방화벽 오픈
#   ./run.sh setup        # venv 생성 + pip install + PostgreSQL 컨테이너 기동
#   ./run.sh pipeline     # collect → preprocess → load 한 번에 실행
#   ./run.sh serve        # Flask 웹서비스 실행 (포트 ${FLASK_PORT})
#   ./run.sh all          # setup + pipeline + serve
#
# 환경변수로 재정의 가능:
#   PYTHON_BIN   (default: python3)
#   FLASK_PORT   (default: 3000)
#
# 참고: docker 관련 명령은 모두 sudo로 실행됩니다.
#       중간에 sudo 암호를 물어볼 수 있습니다.
# ============================================================================

set -euo pipefail

# --- 기본 설정 ---------------------------------------------------------------
VENV_DIR="venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"
FLASK_PORT="${FLASK_PORT:-3000}"

# --- 유틸 --------------------------------------------------------------------
log() { printf '\n\033[1;34m[run.sh]\033[0m %s\n' "$*"; }
err() { printf '\n\033[1;31m[run.sh]\033[0m %s\n' "$*" >&2; }

usage() {
  cat <<EOF
Usage: $0 [command]

기본 동작 (인자 없이 실행 시): setup → serve
                              (외부 fetch 없이 웹서비스만 기동)

Commands:
  bootstrap   OS 패키지·Docker·firewalld 설정 (sudo 필요, 1회만)
  setup       Python venv 생성 + 의존성 설치 + PostgreSQL 컨테이너 기동
  collect     외부 소스에서 원본 데이터 수집
  preprocess  전처리 (결측치, 해시 정규화, CVE 파싱, ATT&CK 매칭)
  load        PostgreSQL 적재 (매 실행마다 전체 갱신)
  pipeline    collect → preprocess → load 한 번에 (데이터 갱신 필요할 때)
  serve       Flask 웹서비스 실행 (포트 ${FLASK_PORT})
  all         setup → serve (기본값)
  fresh       setup → pipeline → serve (데이터 새로 받아오고 실행)

환경변수:
  PYTHON_BIN   Python 실행 파일 (default: python3)
  FLASK_PORT   Flask 포트       (default: 3000)
EOF
}

# docker compose v2(플러그인) 우선, 없으면 docker-compose(v1) 사용 (sudo)
dc() {
  if sudo docker compose version >/dev/null 2>&1; then
    sudo docker compose "$@"
  else
    sudo docker-compose "$@"
  fi
}

activate_venv() {
  if [[ ! -d "$VENV_DIR" ]]; then
    err "venv가 없습니다. 먼저 './run.sh setup' 실행하세요."
    exit 1
  fi
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
}

# --- bootstrap: OS/도구 설치 (sudo, 1회) -------------------------------------
cmd_bootstrap() {
  log "1) OS 패키지 업데이트 및 필수 도구 설치"
  sudo dnf -y install git python3 python3-pip python3-virtualenv \
                     dnf-plugins-core firewalld

  log "2) Docker CE 저장소 등록 및 설치"
  if ! command -v docker >/dev/null 2>&1; then
    sudo dnf config-manager \
      --add-repo=https://download.docker.com/linux/centos/docker-ce.repo
    sudo dnf -y install docker-ce docker-ce-cli containerd.io \
                        docker-compose-plugin
  else
    log "   docker 이미 설치됨 → 건너뜀"
  fi

  log "3) Docker 서비스 활성화"
  sudo systemctl enable --now docker

  log "4) firewalld에서 ${FLASK_PORT}/tcp Ingress 허용"
  sudo systemctl enable --now firewalld
  sudo firewall-cmd --permanent --add-port="${FLASK_PORT}/tcp"
  sudo firewall-cmd --reload

  log "bootstrap 완료. 이제 './run.sh setup' 실행하세요."
  log "OCI VCN Security List/NSG에서도 TCP ${FLASK_PORT} Ingress를 허용해야 외부 접속 가능"
}

# --- setup: venv, pip, docker compose ---------------------------------------
cmd_setup() {
  log "1) Python venv 생성"
  if [[ ! -d "$VENV_DIR" ]]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
  else
    log "   venv 이미 존재 → 건너뜀"
  fi

  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"

  log "2) pip 업그레이드 및 requirements 설치"
  pip install --upgrade pip
  pip install -r requirements.txt

  log "3) Docker 서비스 상태 확인"
  if ! sudo systemctl is-active --quiet docker; then
    sudo systemctl start docker
  fi

  log "4) .env 파일 확인"
  if [[ ! -f .env ]]; then
    err ".env 파일이 없습니다. MalwareBazaar API 키/DB 정보를 채워주세요."
    err "   MalwareBazaar API 키 발급: https://bazaar.abuse.ch/account/"
    err "   docker-compose.yml 기본값과 맞춰 작성"
    exit 1
  fi

  log "5) PostgreSQL 컨테이너 기동 (sudo docker compose up -d)"
  dc up -d

  log "setup 완료"
}

# --- 파이프라인 단계별 --------------------------------------------------------
cmd_collect()    { activate_venv; python run_pipeline.py collect; }
cmd_preprocess() { activate_venv; python run_pipeline.py preprocess; }
cmd_load()       { activate_venv; python run_pipeline.py load; }
cmd_pipeline()   { activate_venv; python run_pipeline.py all; }

# --- 웹서비스 ----------------------------------------------------------------
cmd_serve() {
  activate_venv
  log "Flask 웹서비스 시작 (포트 ${FLASK_PORT})"
  log "   외부 접속: http://<VM_PUBLIC_IP>:${FLASK_PORT}"
  log "   백그라운드 유지: nohup ./run.sh serve > server.log 2>&1 &"
  FLASK_PORT="$FLASK_PORT" python -m app.app
}

cmd_all() {
  cmd_setup
  cmd_serve
}

# --- 파이프라인 전체 (collect + preprocess + load) --- 명시적으로만 실행 ------
cmd_pipeline_all() {
  cmd_setup
  cmd_pipeline
  cmd_serve
}

# --- 진입점 -----------------------------------------------------------------
case "${1:-}" in
  bootstrap)  cmd_bootstrap ;;
  setup)      cmd_setup ;;
  collect)    cmd_collect ;;
  preprocess) cmd_preprocess ;;
  load)       cmd_load ;;
  pipeline)   cmd_pipeline ;;
  serve)      cmd_serve ;;
  all|"")     cmd_all ;;
  fresh)      cmd_pipeline_all ;;
  -h|--help|help) usage ;;
  *) err "알 수 없는 명령: $1"; usage; exit 1 ;;
esac