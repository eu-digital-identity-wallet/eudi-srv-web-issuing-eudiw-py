import pytest

@pytest.fixture(autouse=True)
def mock_configuration(monkeypatch):
    
    config = {
        "service_url": "https://service.test"
    }
    
    monkeypatch.setattr("app.CONFIGURATION", config)
    monkeypatch.setattr("app.dynamic_func.CONFIGURATION", config)
    monkeypatch.setattr("app.formatter_func.CONFIGURATION", config)
    monkeypatch.setattr("app.misc.CONFIGURATION", config)
    monkeypatch.setattr("app.preauthorization.CONFIGURATION", config)
    monkeypatch.setattr("app.revocation.CONFIGURATION", config)
    monkeypatch.setattr("app.route_dynamic.CONFIGURATION", config)
    monkeypatch.setattr("app.route_formatter.CONFIGURATION", config)
    monkeypatch.setattr("app.route_oid4vp.CONFIGURATION", config)
    monkeypatch.setattr("app.route_oidc.CONFIGURATION", config)
    monkeypatch.setattr("app.signed_metadata.CONFIGURATION", config)
    
    yield config