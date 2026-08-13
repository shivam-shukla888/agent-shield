from fastapi.testclient import TestClient

from app import __version__
from app.main import app

client = TestClient(app)


def test_health_check() -> None:
    """Test that GET /health returns HTTP 200 and status ok with version."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == __version__
