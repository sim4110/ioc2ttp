#flask REST API main
import os

from dotenv import load_dotenv
from flask import Flask, render_template
from flask_cors import CORS

from app.api import api_bp

load_dotenv()

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, "templates"),
        static_folder=os.path.join(BASE_DIR, "static"),
    )
    CORS(app)
    app.register_blueprint(api_bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_ENV", "development") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
