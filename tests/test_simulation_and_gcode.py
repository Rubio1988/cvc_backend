# tests/test_simulation_and_gcode.py
import os
import io
import pytest
from fastapi.testclient import TestClient
import json

# Ajustar path para importar app
test_dir = os.path.dirname(os.path.dirname(__file__))
import sys
sys.path.append(test_dir)

from main import app, UPLOAD_DIR, engine, Base

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_db_and_upload():
    # Reset BD y directorios
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            os.remove(os.path.join(UPLOAD_DIR, f))
    else:
        os.makedirs(UPLOAD_DIR)
    # Register & login user
    signup = client.post("/signup", json={
        "username": "simuser",
        "password": "SimPass123",
        "email": "sim@example.com",
        "full_name": "Sim User"
    })
    assert signup.status_code == 200
    token_res = client.post(
        "/token",
        data={"username": "simuser", "password": "SimPass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert token_res.status_code == 200
    token = token_res.json()["access_token"]

    # Upload a simple SVG
    svg = b'<svg height="10" width="10"><rect width="10" height="10"/></svg>'
    fobj = io.BytesIO(svg)
    fobj.name = "sim.svg"
    upload_res = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": (fobj.name, fobj, "image/svg+xml")}
    )
    assert upload_res.status_code == 200
    project_id = upload_res.json()["project_id"]
    return {"token": token, "project_id": project_id}

def test_simulation_endpoint(setup_db_and_upload):
    token = setup_db_and_upload["token"]
    project_id = setup_db_and_upload["project_id"]
    res = client.get(
        f"/simulation/{project_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res.status_code == 200
    data = res.json()
    assert "simulation" in data
    sim = data["simulation"]
    assert "vectors" in sim and isinstance(sim["vectors"], list)
    assert "params" in sim and isinstance(sim["params"], dict)
    # Check default params keys
    for key in ("feed_rate", "spindle_speed", "tool_diameter", "pass_depth"):
        assert key in sim["params"]

def test_gcode_endpoint_and_download(setup_db_and_upload, tmp_path):
    token = setup_db_and_upload["token"]
    project_id = setup_db_and_upload["project_id"]

    # Call G-code generation
    gcode_res = client.post(
        "/gcode",
        json={
            "project_id": project_id,
            "feed_rate": 500,
            "spindle_speed": 8000,
            "tool_diameter": 2.0,
            "pass_depth": 0.5
        },
        headers={"Authorization": f"Bearer {token}"}
    )
    assert gcode_res.status_code == 200
    gcode_url = gcode_res.json().get("gcode_url")
    assert gcode_url

    # Download the generated .nc file
    download_res = client.get(
        gcode_url,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert download_res.status_code == 200
    content = download_res.text
    # Should contain G-code header markers
    assert f"G-code for project {project_id}" in content or "; CNC VisionCut G-code" in content

    # Optionally save to temporary path for manual inspection
    file_path = tmp_path / f"{project_id}.nc"
    file_path.write_text(content)
