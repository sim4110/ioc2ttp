"""웹서비스(Flask) 프로세스 안에서 파이프라인을 매일 자동 실행하는 백그라운드 스케줄러.

별도 cron/systemd 등록 없이 `python -m app.app`로 웹서버를 띄워두는 동안에만
동작한다 (README 6장 "파이프라인 수동 실행" 한계에 대한 대안 — OCI VM에 cron을
따로 등록하지 않아도 되지만, 그만큼 Flask 프로세스가 떠 있는 동안에만 스케줄이
유지된다는 트레이드오프가 있다).
"""
import datetime
import os
import threading
import time
import traceback

_LOCK = threading.Lock()
_started = False


def _seconds_until(hour: int, minute: int) -> float:
    now = datetime.datetime.now()
    target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if target <= now:
        target += datetime.timedelta(days=1)
    return (target - now).total_seconds()


def _run_pipeline_once() -> None:
    import run_pipeline

    print(f"[scheduler] {datetime.datetime.now().isoformat()} 파이프라인 실행 시작")
    try:
        run_pipeline.step_collect()
        run_pipeline.step_preprocess()
        run_pipeline.step_load()
        print(f"[scheduler] {datetime.datetime.now().isoformat()} 파이프라인 실행 완료")
    except Exception:  # noqa: BLE001 - 스케줄러 스레드가 죽지 않고 다음 주기에 재시도하도록 흡수
        print(f"[scheduler] {datetime.datetime.now().isoformat()} 파이프라인 실행 실패")
        traceback.print_exc()


def _loop(hour: int, minute: int) -> None:
    while True:
        wait_seconds = _seconds_until(hour, minute)
        print(
            f"[scheduler] 다음 파이프라인 실행까지 {wait_seconds / 3600:.1f}시간 대기 "
            f"(매일 {hour:02d}:{minute:02d})"
        )
        time.sleep(wait_seconds)
        _run_pipeline_once()


def start_daily_pipeline(hour: int = 3, minute: int = 0) -> None:
    """매일 지정 시각에 run_pipeline.py의 collect→preprocess→load를 실행하는
    데몬 스레드를 시작한다. 앱 프로세스당 한 번만 시작되도록 가드한다
    (Flask 디버그 리로더가 동일 코드를 두 번 로드하는 것을 방지)."""
    global _started
    with _LOCK:
        if _started:
            return
        _started = True

    thread = threading.Thread(
        target=_loop, args=(hour, minute), daemon=True, name="pipeline-scheduler"
    )
    thread.start()
    print(f"[scheduler] 매일 {hour:02d}:{minute:02d} 파이프라인 자동 실행 스케줄러 시작 (pid={os.getpid()})")
