###############################################################################
# Copyright (c) 2026 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################
"""Tests for loading and processing the issuer YAML configuration."""

import sys

import pytest
import yaml

from app.core import config


def _write(path, content: bytes) -> str:
    path.write_bytes(content)
    return str(path)


@pytest.fixture
def config_files(tmp_path):
    """A minimal valid configuration whose key / certificate paths exist."""
    files = {
        "fe_key": _write(tmp_path / "fe.key", b"FE-KEY"),
        "fe_cert": _write(tmp_path / "fe.crt", b"FE-CERT"),
        "nonce": _write(tmp_path / "nonce.pem", b"NONCE-KEY"),
        "enc": _write(tmp_path / "enc.pem", b"ENC-KEY"),
        "fc_key": _write(tmp_path / "fc.pem", b"FC-KEY"),
        "fc_cert": _write(tmp_path / "fc.der", b"FC-CERT"),
        "fe_fc_key": _write(tmp_path / "fe-fc.pem", b"FE-FC-KEY"),
        "fe_fc_cert": _write(tmp_path / "fe-fc.der", b"FE-FC-CERT"),
    }
    data = {
        "service_url": "https://backend.test",
        "frontend": {
            "default": "fe1",
            "frontends_config": {
                "fe1": {
                    "url": "https://frontend.test",
                    "metadata_signing_key_path": files["fe_key"],
                    "metadata_access_certificate_path": files["fe_cert"],
                }
            },
        },
        "keys": {"nonce_path": files["nonce"], "credential_request_path": files["enc"]},
        "countries": {
            "FC": {
                "keys": {
                    "_default": {"private_key_path": files["fc_key"], "certificate_path": files["fc_cert"]},
                    "fe1": {"private_key_path": files["fe_fc_key"], "certificate_path": files["fe_fc_cert"]},
                }
            }
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(data))
    return config_path


class TestLoadConfig:
    def test_valid_file_is_processed(self, config_files):
        loaded = config.load_config(str(config_files))

        frontend = loaded["frontend"]["frontends_config"]["fe1"]
        assert frontend["metadata_signing_key"] == b"FE-KEY"
        assert frontend["metadata_access_certificate"] == b"FE-CERT"
        assert loaded["keys"]["nonce_key"] == b"NONCE-KEY"
        assert loaded["keys"]["credential_encryption_key"] == b"ENC-KEY"
        country_keys = loaded["countries"]["FC"]["keys"]
        assert (country_keys["_default"]["private_key"], country_keys["_default"]["certificate"]) == (
            b"FC-KEY",
            b"FC-CERT",
        )
        assert country_keys["fe1"]["private_key"] == b"FE-FC-KEY"
        # Paths are kept next to the loaded bytes.
        assert country_keys["_default"]["private_key_path"].endswith("fc.pem")

    def test_path_from_environment(self, config_files, monkeypatch):
        monkeypatch.setenv("ISSUER_CONFIG_PATH", str(config_files))
        assert config.load_config()["service_url"] == "https://backend.test"

    def test_default_path_used_without_environment(self, monkeypatch):
        monkeypatch.delenv("ISSUER_CONFIG_PATH", raising=False)
        with pytest.raises(RuntimeError, match=config.DEFAULT_CONFIG_PATH):
            config.load_config()

    def test_missing_file(self, tmp_path):
        with pytest.raises(RuntimeError, match="Config file not found"):
            config.load_config(str(tmp_path / "nope.yaml"))

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        with pytest.raises(RuntimeError, match="Config file is empty"):
            config.load_config(str(empty))

    def test_invalid_yaml(self, tmp_path):
        broken = tmp_path / "broken.yaml"
        broken.write_text("service_url: [unclosed")
        with pytest.raises(RuntimeError, match="Invalid YAML"):
            config.load_config(str(broken))

    def test_missing_key_file(self, config_files, tmp_path):
        data = yaml.safe_load(config_files.read_text())
        data["keys"]["nonce_path"] = str(tmp_path / "missing.pem")
        config_files.write_text(yaml.safe_dump(data))

        with pytest.raises(OSError):
            config.load_config(str(config_files))

    def test_missing_section(self, tmp_path):
        partial = tmp_path / "partial.yaml"
        partial.write_text(yaml.safe_dump({"service_url": "x"}))
        with pytest.raises(KeyError):
            config.load_config(str(partial))


@pytest.mark.parametrize("frontend_id", ["fe/1", "fe.1", "fe 1", "fé"])
def test_frontend_id_must_be_a_path_segment(config_files, frontend_id):
    # The id ends the frontend's authorization server issuer: <base_url>/<id>.
    data = yaml.safe_load(config_files.read_text())
    frontends = data["frontend"]["frontends_config"]
    frontends[frontend_id] = frontends.pop("fe1")
    config_files.write_text(yaml.safe_dump(data))
    with pytest.raises(RuntimeError, match="may only contain letters, digits"):
        config.load_config(str(config_files))


class TestRegistrationCertificate:
    JWT = "eyJ0eXAiOiJyYy13cnArand0In0.eyJuYW1lIjoiSXNzdWVyIn0.c2ln"

    def _set_path(self, config_files, path):
        data = yaml.safe_load(config_files.read_text())
        data["frontend"]["frontends_config"]["fe1"]["registration_certificate_path"] = str(path)
        config_files.write_text(yaml.safe_dump(data))

    def test_loaded_and_stripped(self, config_files, tmp_path):
        cert = tmp_path / "wrprc.jwt"
        cert.write_text(f"  {self.JWT}\n")
        self._set_path(config_files, cert)

        frontend = config.load_config(str(config_files))["frontend"]["frontends_config"]["fe1"]
        assert frontend["registration_certificate"] == self.JWT

    def test_optional(self, config_files):
        frontend = config.load_config(str(config_files))["frontend"]["frontends_config"]["fe1"]
        assert "registration_certificate" not in frontend

    @pytest.mark.parametrize("content", [b"not a jwt", b"a..c", b"a.b.c.d", b"\xff.\xfe.\xfd"])
    def test_not_a_jwt(self, config_files, tmp_path, content):
        cert = tmp_path / "wrprc.jwt"
        cert.write_bytes(content)
        self._set_path(config_files, cert)

        with pytest.raises(RuntimeError, match="Registration certificate of frontend fe1 is not a JWT"):
            config.load_config(str(config_files))

    def test_missing_file(self, config_files, tmp_path):
        self._set_path(config_files, tmp_path / "missing.jwt")
        with pytest.raises(OSError):
            config.load_config(str(config_files))


class TestVariables:
    def test_load_config_resolves_paths(self, config_files, tmp_path):
        data = yaml.safe_load(config_files.read_text())
        data["variables"] = {"base": "https://backend.test", "dir": str(tmp_path)}
        data["service_url"] = "${base}"
        data["keys"]["nonce_path"] = "${dir}/nonce.pem"
        config_files.write_text(yaml.safe_dump(data))

        loaded = config.load_config(str(config_files))

        assert "variables" not in loaded
        assert loaded["service_url"] == "https://backend.test"
        assert loaded["keys"]["nonce_key"] == b"NONCE-KEY"

    def test_nested_values_and_earlier_variables(self):
        resolved = config.resolve_variables(
            {
                "variables": {"root": "/etc/eudiw", "keys_dir": "${root}/privKey"},
                "countries": {"PT": {"keys": {"_default": {"private_key_path": "${keys_dir}/PT.pem"}}}},
                "trusted": ["${root}/cert/", 5, None],
            }
        )

        assert resolved["countries"]["PT"]["keys"]["_default"]["private_key_path"] == "/etc/eudiw/privKey/PT.pem"
        assert resolved["trusted"] == ["/etc/eudiw/cert/", 5, None]

    def test_without_variables_section(self):
        assert config.resolve_variables({"service_url": "https://backend.test"}) == {
            "service_url": "https://backend.test"
        }

    def test_yaml_aliases_become_independent(self):
        data = yaml.safe_load("a: &auth {base_url: x}\nb: *auth\n")
        resolved = config.resolve_variables(data)

        resolved["a"]["base_url"] = "changed"
        assert resolved["b"]["base_url"] == "x"

    def test_undefined_variable(self):
        with pytest.raises(RuntimeError, match=r"Undefined config variable: \$\{missing\}"):
            config.resolve_variables({"service_url": "${missing}/x"})

    def test_variable_used_before_its_definition(self):
        with pytest.raises(RuntimeError, match="Undefined config variable"):
            config.resolve_variables({"variables": {"a": "${b}", "b": "x"}})

    @pytest.mark.parametrize("variables", [["a"], {"port": 5432}])
    def test_invalid_variables(self, variables):
        with pytest.raises(RuntimeError, match="variables|must be a string"):
            config.resolve_variables({"variables": variables})

    def test_example_configuration_resolves(self):
        with open("app/config_issuer_backend_example.yaml") as f:
            resolved = config.resolve_variables(yaml.safe_load(f))

        assert "${" not in yaml.safe_dump(resolved)
        for code in ("FC", "AV", "AV2"):
            assert resolved["countries"][code]["issuing_country"] == "LU"
            assert resolved["countries"][code]["un_distinguishing_sign"] == "LU"
        # formatters.py reads private_key_password of every document signer.
        for country in resolved["countries"].values():
            assert "private_key_password" in country["keys"]["_default"]


def test_mock_config_shape():
    # No database settings: tests never connect to Postgres.
    assert config.mock_config() == {"expiry": {"session": 30}}


class TestDetectTestEnv:
    @pytest.fixture(autouse=True)
    def _clean(self, monkeypatch):
        monkeypatch.delenv("EUDIW_TEST_ENV", raising=False)
        monkeypatch.setattr(sys, "argv", ["flask", "run"])

    def test_production_like_process(self):
        assert config._detect_test_env() is False

    def test_explicit_opt_in(self, monkeypatch):
        monkeypatch.setenv("EUDIW_TEST_ENV", "true")
        assert config._detect_test_env() is True

    @pytest.mark.parametrize("value", ["false", "1", "TRUE", ""])
    def test_opt_in_must_be_true(self, monkeypatch, value):
        monkeypatch.setenv("EUDIW_TEST_ENV", value)
        assert config._detect_test_env() is False

    def test_pytest_alone_does_not_enable_it(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["/usr/bin/pytest", "-q"])
        assert "pytest" in sys.modules
        assert config._detect_test_env() is False
