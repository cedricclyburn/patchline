from flask import Flask, jsonify, request

from .profiles import ProfileError, parse_profile
from .report import render

app = Flask(__name__)
_profiles: dict[str, dict] = {}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "profiles": len(_profiles)}


@app.post("/profiles")
def upload_profile():
    try:
        profile = parse_profile(request.get_data(as_text=True))
    except ProfileError as exc:
        return jsonify(error=str(exc)), 400
    _profiles[profile["mission"]] = profile
    return jsonify(mission=profile["mission"], waypoints=len(profile["waypoints"])), 201


@app.get("/profiles/<mission>/report")
def report(mission: str):
    profile = _profiles.get(mission)
    if profile is None:
        return jsonify(error="unknown mission"), 404
    return render(profile), 200, {"Content-Type": "text/html"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
