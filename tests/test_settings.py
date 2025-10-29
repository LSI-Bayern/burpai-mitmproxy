import json

import pytest

from src.settings import PlatformDefaults, Settings


@pytest.fixture
def mock_ask(mocker):
    mock = mocker.patch("src.settings.ask")
    mock.return_value = ""
    return mock


@pytest.fixture
def mock_ask_yn(mocker):
    mock = mocker.patch("src.settings.ask_yn")
    mock.return_value = True
    return mock


@pytest.fixture
def temp_settings_path(tmp_path):
    return tmp_path / ".config" / "burpai" / "settings.json"


@pytest.fixture
def mock_vault(mocker):
    vault = mocker.MagicMock()
    vault.is_available = True
    vault.__iter__ = lambda _self: iter(vault.keys())
    vault.__contains__ = lambda _self, key: key in vault.keys()  # noqa: SIM118
    mocker.patch("src.settings.Vault", return_value=vault)
    return vault


@pytest.fixture
def mock_platform_defaults(mocker, tmp_path):
    def get_defaults():
        return PlatformDefaults(
            burpsuite_dir=str(tmp_path / "BurpSuitePro"),
            burpsuite_config_dir=str(tmp_path / ".BurpSuite"),
            mitmproxy_config_dir=str(tmp_path / ".mitmproxy"),
            burpai_config_path=str(tmp_path / ".config" / "burpai" / "settings.json"),
        )

    mocker.patch.object(Settings, "_get_platform_defaults", side_effect=get_defaults)
    return get_defaults


class TestSettingsInitialization:
    @pytest.mark.usefixtures("mock_vault", "mock_platform_defaults")
    def test_creates_empty_config_file(self, temp_settings_path):
        settings = Settings()

        assert settings.load_config()
        assert temp_settings_path.exists()
        assert json.loads(temp_settings_path.read_text()) == {}

    @pytest.mark.usefixtures("mock_vault")
    @pytest.mark.parametrize(
        "platform_name,expected_burpsuite_dir",
        [
            ("Linux", "~/BurpSuitePro"),
            ("Darwin", "/Applications/Burp Suite Professional.app"),
            ("Windows", "~/AppData/Local/Programs/BurpSuitePro"),
        ],
    )
    def test_platform_specific_defaults(self, mocker, platform_name, expected_burpsuite_dir):
        mocker.patch("src.settings.platform.system", return_value=platform_name)

        settings = Settings()

        assert settings.schema["burpsuite_dir"].default == expected_burpsuite_dir


class TestCorruptedConfig:
    @pytest.mark.usefixtures("mock_vault", "mock_platform_defaults")
    def test_invalid_json_returns_false(self, temp_settings_path):
        temp_settings_path.parent.mkdir(parents=True, exist_ok=True)
        temp_settings_path.write_text("{invalid json}")

        settings = Settings()
        result = settings.load_config()

        assert not result


class TestSecretDeletion:
    @pytest.mark.usefixtures("mock_platform_defaults")
    def test_delete_secrets_clears_vault_and_tracking(self, mock_vault, mock_ask_yn):
        mock_ask_yn.return_value = True
        mock_vault.keys.return_value = ["api_key", "proxy_password"]

        settings = Settings()
        settings.load_config()
        settings.delete_secrets()

        assert mock_vault.delete.call_count == 2  # noqa: PLR2004
        mock_vault.delete.assert_any_call("api_key")
        mock_vault.delete.assert_any_call("proxy_password")

    @pytest.mark.usefixtures("mock_platform_defaults")
    def test_delete_secrets_respects_user_cancellation(self, mock_vault, mock_ask_yn):
        mock_ask_yn.return_value = False

        settings = Settings()
        settings.load_config()
        settings.delete_secrets()

        mock_vault.delete.assert_not_called()

    @pytest.mark.usefixtures("mock_platform_defaults")
    def test_delete_secrets_non_interactive_mode(self, mock_vault, mock_ask):
        mock_vault.keys.return_value = ["api_key"]

        settings = Settings()
        settings.load_config()
        settings.delete_secrets(interactive=False)

        mock_ask.assert_not_called()
        mock_vault.delete.assert_called_once_with("api_key")


class TestNoAuthUrls:
    @pytest.mark.usefixtures("mock_ask", "mock_platform_defaults")
    def test_no_api_key_required_for_localhost(self, mock_vault, temp_settings_path):
        temp_settings_path.parent.mkdir(parents=True, exist_ok=True)

        config = {
            "model": "test-model",
            "port": 8080,
            "token_limit": 32000,
            "llm_url": "http://localhost:11434/v1",
        }
        temp_settings_path.write_text(json.dumps(config))

        mock_vault.keys.return_value = []

        settings = Settings()
        settings.load_config()
        result = settings.resolve(overrides=None)

        assert result["api_key"] is None


class TestTypeConversion:
    @pytest.mark.usefixtures("mock_vault", "mock_ask", "mock_platform_defaults")
    def test_returns_none_on_invalid_type(self, temp_settings_path):
        temp_settings_path.parent.mkdir(parents=True, exist_ok=True)

        config = {
            "model": "test-model",
            "port": "not-a-number",
            "token_limit": 32000,
            "llm_url": "http://localhost:11434/v1",
        }
        temp_settings_path.write_text(json.dumps(config))

        settings = Settings()
        settings.load_config()

        result = settings.resolve(overrides=None)

        assert result is None


class TestResolve:
    @pytest.mark.usefixtures("mock_ask", "mock_platform_defaults")
    def test_retrieves_complete_configuration(self, mock_vault, temp_settings_path):
        temp_settings_path.parent.mkdir(parents=True, exist_ok=True)

        config = {
            "model": "test-model",
            "port": 9000,
            "token_limit": 20000,
            "llm_url": "http://192.168.1.100:11434/v1",
        }
        temp_settings_path.write_text(json.dumps(config))

        api_key = "sk-1234567890"
        mock_vault.keys.return_value = ["api_key@http://192.168.1.100:11434/v1"]
        mock_vault.get.return_value = api_key

        settings = Settings()
        settings.load_config()
        result = settings.resolve(overrides=None)

        assert result["model"] == config["model"]
        assert result["port"] == config["port"]
        assert result["token_limit"] == config["token_limit"]
        assert result["llm_url"] == config["llm_url"]
        assert result["api_key"] == api_key

    @pytest.mark.usefixtures("mock_ask", "mock_platform_defaults")
    def test_overrides_apply_to_all_settings(self, mock_vault, temp_settings_path):
        temp_settings_path.parent.mkdir(parents=True, exist_ok=True)

        config = {
            "model": "test-model",
            "port": 16001,
            "token_limit": 48000,
            "llm_url": "http://localhost:11434/v1",
        }
        temp_settings_path.write_text(json.dumps(config))

        mock_vault.get.return_value = None

        settings = Settings()
        settings.load_config()
        overrides = {
            "model": "new-model",
            "llm_url": "https://api.example.com/v1",
        }
        result = settings.resolve(overrides=overrides)

        assert result["model"] == overrides["model"]
        assert result["llm_url"] == overrides["llm_url"]

        assert result["port"] == config["port"]
        assert result["token_limit"] == config["token_limit"]


class TestReset:
    @pytest.mark.usefixtures("mock_platform_defaults")
    def test_clears_directory_and_secrets_on_confirmation(self, mock_vault, temp_settings_path, mock_ask_yn):
        temp_settings_path.parent.mkdir(parents=True, exist_ok=True)
        temp_settings_path.write_text(json.dumps({"model": "test-model"}))

        mock_ask_yn.return_value = True
        mock_vault.is_available = True
        mock_vault.keys.return_value = ["api_key"]

        settings = Settings()
        settings.load_config()
        settings.reset()

        assert not temp_settings_path.parent.exists()
        mock_vault.delete.assert_called_once_with("api_key")

    @pytest.mark.usefixtures("mock_vault", "mock_platform_defaults")
    def test_respects_user_cancellation(self, temp_settings_path, mock_ask_yn):
        temp_settings_path.parent.mkdir(parents=True, exist_ok=True)
        temp_settings_path.write_text(json.dumps({"model": "test-model"}))

        mock_ask_yn.return_value = False

        settings = Settings()
        settings.load_config()
        settings.reset()

        assert temp_settings_path.parent.exists()
