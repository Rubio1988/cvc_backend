# tests/test_main.py
# Pruebas unitarias para endpoints de Auth y upload
import os
import io
import pytest
from fastapi.testclient import TestClient

# Importar la app de FastAPI
test_dir = os.path.dirname(os.path.dirname(__file__))
import sys
sys.path.append(os.path.abspath(test_dir))

from main import app, UPLOAD_DIR, engine, Base

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def setup_and_teardown():
    # Reiniciar base de datos eliminando tablas y recreándolas
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    # Asegurarse de directorios limpios
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            os.remove(os.path.join(UPLOAD_DIR, f))
    else:
        os.makedirs(UPLOAD_DIR)
    yield
    # Limpieza final: borrar archivos y datos en BD
    if os.path.exists(UPLOAD_DIR):
        for f in os.listdir(UPLOAD_DIR):
            os.remove(os.path.join(UPLOAD_DIR, f))
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_signup_and_token_and_upload():
    # 1. Registrar usuario
    signup_payload = {
        "username": "testuser",
        "password": "TestPass123",
        "email": "testuser@example.com",
        "full_name": "Test User"
    }
    res_signup = client.post("/signup", json=signup_payload)
    assert res_signup.status_code == 200
    data_signup = res_signup.json()
    assert data_signup["username"] == "testuser"
    assert data_signup["email"] == "testuser@example.com"

    # 2. Obtener token
    token_payload = {"username": "testuser", "password": "TestPass123"}
    res_token = client.post(
        "/token",
        data=token_payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert res_token.status_code == 200
    data_token = res_token.json()
    assert "access_token" in data_token
    token = data_token["access_token"]

    # 3. Llamar endpoint protegido /users/me
    res_me = client.get(
        "/users/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert res_me.status_code == 200
    data_me = res_me.json()
    assert data_me["username"] == "testuser"

    # 4. Probar /upload
    svg_content = b'<svg height="10" width="10"><rect width="10" height="10"/></svg>'
    file_obj = io.BytesIO(svg_content)
    file_obj.name = "test.svg"
    res_upload = client.post(
        "/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": (file_obj.name, file_obj, "image/svg+xml")}  # Content type flexible
    )
    assert res_upload.status_code == 200
    data_upload = res_upload.json()
    assert "project_id" in data_upload
    project_id = data_upload["project_id"]
    # Verificar que el archivo se guardó
    saved_files = os.listdir(UPLOAD_DIR)
    assert any(project_id in fname for fname in saved_files)

