"""Flask REST API 엔드포인트 (project.pdf 5-2 서비스 페이지 구성과 매핑)."""
from flask import Blueprint, jsonify, request

from app import llm_service, model

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _handle(fn, *args, **kwargs):
    try:
        return jsonify(fn(*args, **kwargs))
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 500


@api_bp.route("/meta")
def meta():
    return _handle(model.get_meta)


@api_bp.route("/dashboard/top-signatures")
def top_signatures():
    n = request.args.get("n", default=10, type=int)
    return _handle(model.get_top_signatures, n)


@api_bp.route("/dashboard/top-yara-rules")
def top_yara_rules():
    n = request.args.get("n", default=10, type=int)
    return _handle(model.get_top_yara_rules, n)


@api_bp.route("/dashboard/timeseries")
def timeseries():
    return _handle(model.get_timeseries)


@api_bp.route("/dashboard/filetypes")
def filetypes():
    return _handle(model.get_filetype_distribution)


@api_bp.route("/sample/<sha256_hash>")
def sample_detail(sha256_hash):
    result = model.get_sample_detail(sha256_hash)
    if not result:
        return jsonify({"error": "sample not found"}), 404
    return jsonify(result)


@api_bp.route("/sample/<sha256_hash>/analyze", methods=["POST"])
def sample_analyze(sha256_hash):
    sample = model.get_sample_detail(sha256_hash)
    if not sample:
        return jsonify({"error": "sample not found"}), 404
    try:
        return jsonify(llm_service.analyze_sample(sample))
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": str(exc)}), 502


@api_bp.route("/sample/search")
def sample_search():
    q = request.args.get("q", default="", type=str)
    if not q:
        return jsonify([])
    return _handle(model.search_samples, q)


@api_bp.route("/attack/mapping-rate")
def attack_mapping_rate():
    return _handle(model.get_attack_mapping_rate)


@api_bp.route("/attack/techniques")
def attack_techniques():
    n = request.args.get("n", default=10, type=int)
    return _handle(model.get_top_techniques, n)


@api_bp.route("/attack/matrix")
def attack_matrix():
    return _handle(model.get_attack_matrix)


@api_bp.route("/drivers/category")
def drivers_category():
    return _handle(model.get_driver_category_distribution)


@api_bp.route("/attack/groups")
def attack_groups():
    return _handle(model.get_available_groups)


@api_bp.route("/attack/group/<local_tag>")
def attack_group_chain(local_tag):
    result = model.get_group_attack_chain(local_tag)
    if not result:
        return jsonify({"error": "group not found or not resolved to MITRE ATT&CK"}), 404
    return jsonify(result)
