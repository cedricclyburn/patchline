import pytest

from app.profiles import ProfileError, Vector, parse_profile
from app.server import app

PROFILE = """
mission: CRS-41
vehicle: F9-B1092
waypoints:
  - name: MECO
    position: !vector [6471000, 0, 0]
  - name: SECO
    position: !vector [6571000, 1200, -40]
"""


def test_parses_vector_tags():
    profile = parse_profile(PROFILE)
    assert profile["waypoints"][0]["position"] == Vector(6471000.0, 0.0, 0.0)


def test_rejects_missing_fields():
    with pytest.raises(ProfileError):
        parse_profile("mission: X\n")


def test_rejects_untagged_position():
    with pytest.raises(ProfileError):
        parse_profile("mission: X\nvehicle: Y\nwaypoints:\n  - name: A\n    position: [1, 2, 3]\n")


def test_upload_and_report_roundtrip():
    client = app.test_client()
    resp = client.post("/profiles", data=PROFILE)
    assert resp.status_code == 201
    html = client.get("/profiles/CRS-41/report").get_data(as_text=True)
    assert "CRS-41" in html and "6571000.1 m" in html


def test_healthz():
    assert app.test_client().get("/healthz").json["status"] == "ok"
