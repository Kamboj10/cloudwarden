import pytest


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch):
    """Make sure tests can never touch a real AWS account."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def session():
    """A boto3 session backed by moto's in-memory fake AWS."""
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    with moto.mock_aws():
        yield boto3.Session(region_name="us-east-1")
