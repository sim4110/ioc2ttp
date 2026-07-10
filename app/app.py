#flask REST API main
import os

from dotenv import load_dotenv
from flask import Flask, render_template
from flask_cors import CORS

from app import scheduler
from app.api import api_bp

load_dotenv()

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")


def _maybe_start_scheduler() -> None:
    if os.getenv("PIPELINE_SCHEDULER_ENABLED", "true").lower() != "true":
        return
    # FLASK_ENV=development(기본값)면 Werkzeug 리로더가 프로세스를 두 번 띄우는데,
    # 감시용 부모 프로세스(WERKZEUG_RUN_MAIN 미설정)에서는 스케줄러를 켜지 않는다.
    is_dev = os.getenv("FLASK_ENV", "development") == "development"
    if is_dev and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return
    hour = int(os.getenv("PIPELINE_SCHEDULE_HOUR", "3"))
    minute = int(os.getenv("PIPELINE_SCHEDULE_MINUTE", "0"))
    scheduler.start_daily_pipeline(hour=hour, minute=minute)


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "templates"),
        static_folder=os.path.join(BASE_DIR, "static"),
    )
    CORS(app)
    app.register_blueprint(api_bp)

    @app.route("/")
    def landing():
        return render_template("landing.html")

    @app.route("/dashboard")
    def dashboard():
        return render_template("index.html")

    _maybe_start_scheduler()

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_ENV", "development") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
