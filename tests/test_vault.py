import pytest
from keyring.backends import fail, null
from keyring.errors import KeyringError, PasswordDeleteError

from src.vault import Vault


class TestVaultInitialization:
    def test_init_with_working_keyring(self, mocker):
        class WorkingBackend:
            __module__ = "keyring.backends.SecretService"

        mocker.patch("keyring.get_keyring", return_value=WorkingBackend())

        vault = Vault("test-app")

        assert vault.is_available

    def test_init_with_fail_backend(self, mocker):
        mocker.patch("keyring.get_keyring", return_value=fail.Keyring())

        vault = Vault()

        assert not vault.is_available

    def test_init_with_null_backend(self, mocker):
        mocker.patch("keyring.get_keyring", return_value=null.Keyring())

        vault = Vault()

        assert not vault.is_available


class TestVaultGet:
    def test_get_with_available_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mock_get = mocker.patch("keyring.get_password", return_value="secret123")

        vault = Vault("test-app")
        result = vault.get("api_key")

        assert result == "secret123"
        mock_get.assert_called_once_with("test-app", "api_key")

    def test_get_with_unavailable_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=False)

        vault = Vault()
        result = vault.get("api_key")

        assert result is None

    def test_get_with_keyring_error_disables_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mocker.patch("keyring.get_password", side_effect=KeyringError("Error"))

        vault = Vault()
        result = vault.get("api_key")

        assert result is None
        assert not vault.is_available


class TestVaultSet:
    def test_set_with_available_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mock_set = mocker.patch("keyring.set_password")
        mocker.patch("keyring.get_password", return_value=None)

        vault = Vault("test-app")
        vault.set("api_key", "secret123")

        mock_set.assert_any_call("test-app", "api_key", "secret123")
        mock_set.assert_any_call("test-app", "_tracked_keys", '["api_key"]')

    def test_set_with_unavailable_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=False)
        mock_set = mocker.patch("keyring.set_password")

        vault = Vault()
        vault.set("api_key", "secret123")

        mock_set.assert_not_called()

    def test_set_with_keyring_error_disables_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mocker.patch("keyring.set_password", side_effect=KeyringError("Error"))

        vault = Vault()
        vault.set("api_key", "secret123")

        assert not vault.is_available


class TestVaultDelete:
    def test_delete_with_available_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mock_delete = mocker.patch("keyring.delete_password")
        mocker.patch("keyring.get_password", return_value='["api_key"]')

        vault = Vault("test-app")
        vault.delete("api_key")

        mock_delete.assert_any_call("test-app", "api_key")
        mock_delete.assert_any_call("test-app", "_tracked_keys")

    def test_delete_with_unavailable_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=False)
        mock_delete = mocker.patch("keyring.delete_password")

        vault = Vault()
        vault.delete("api_key")

        mock_delete.assert_not_called()

    def test_delete_with_password_delete_error(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mocker.patch("keyring.delete_password", side_effect=PasswordDeleteError("Not found"))

        vault = Vault()
        vault.delete("api_key")

        assert vault.is_available

    def test_delete_with_keyring_error_disables_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mocker.patch("keyring.delete_password", side_effect=KeyringError("Error"))

        vault = Vault()
        vault.delete("api_key")

        assert not vault.is_available


class TestVaultTracking:
    def test_iter_and_contains(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mocker.patch("keyring.get_password", return_value='["api_key", "test123"]')

        vault = Vault()

        assert list(vault) == ["api_key", "test123"]
        assert "api_key" in vault
        assert "test123" in vault
        assert "missing" not in vault

    def test_keys_with_unavailable_vault(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=False)

        vault = Vault()

        assert vault.keys() == []

    def test_set_key_already_tracked(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mock_set = mocker.patch("keyring.set_password")
        mocker.patch("keyring.get_password", return_value='["api_key"]')

        vault = Vault("test-app")
        vault.set("api_key", "new_value")

        mock_set.assert_called_once_with("test-app", "api_key", "new_value")

    def test_delete_key_not_tracked(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mock_delete = mocker.patch("keyring.delete_password")
        mocker.patch("keyring.get_password", return_value='["other_key"]')

        vault = Vault("test-app")
        vault.delete("api_key")

        mock_delete.assert_called_once_with("test-app", "api_key")

    def test_delete_with_remaining_keys(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mocker.patch("keyring.delete_password")
        mock_set = mocker.patch("keyring.set_password")
        mocker.patch("keyring.get_password", return_value='["api_key", "other_key"]')

        vault = Vault("test-app")
        vault.delete("api_key")

        mock_set.assert_called_once_with("test-app", "_tracked_keys", '["other_key"]')

    def test_internal_key_skips_tracking(self, mocker):
        mocker.patch.object(Vault, "_get_availability", return_value=True)
        mock_set = mocker.patch("keyring.set_password")
        mock_delete = mocker.patch("keyring.delete_password")

        vault = Vault("test-app")

        vault.set("_tracked_keys", '["some_key"]')
        mock_set.assert_called_once_with("test-app", "_tracked_keys", '["some_key"]')

        vault.delete("_tracked_keys")
        mock_delete.assert_called_once_with("test-app", "_tracked_keys")
