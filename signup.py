import requests

url = "http://127.0.0.1:8000/signup"
payload = {
    "username": "pepe123",
    "password": "Secreto123",
    "email": "pepe@example.com",
    "full_name": "José Pérez"
}
resp = requests.post(url, json=payload)
print(resp.status_code, resp.json())
