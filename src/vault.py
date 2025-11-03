import json

import keyring
from keyring.backends import fail, null
from keyring.errors import PasswordDeleteError

from .utils import logger


class Vault:
    """Stores secrets in system keyring."""

    def __init__(self, application_name="burpai-mitmproxy"):
        self._application_name = application_name
        self._keys_list_key = "_tracked_keys"
        self.is_available = self._get_availability()

        if not self.is_available:
            logger.info("System keyring will not be used")

    def get(self, key):
        """Return secret or None."""
        if not self.is_available:
            return None
        try:
            return keyring.get_password(self._application_name, key)
        except Exception:
            self.is_available = False
            return None

    def set(self, key, value):
        """Store secret and automatically track it."""
        if not self.is_available:
            return
        try:
            keyring.set_password(self._application_name, key, value)
            if key != self._keys_list_key:
                logger.info("Stored [cyan]%s[/cyan] in the system keyring", key)
                self._track_key(key)
        except Exception:
            self.is_available = False

    def delete(self, key):
        """Delete secret and untrack it."""
        if not self.is_available:
            return
        try:
            keyring.delete_password(self._application_name, key)
            if key != self._keys_list_key:
                logger.info("Deleted [cyan]%s[/cyan] from the system keyring", key)
                self._untrack_key(key)
        except PasswordDeleteError:
            pass
        except Exception:
            self.is_available = False

    def keys(self):
        """Return list of all tracked secret keys from keyring."""
        if not self.is_available:
            return []
        stored = self.get(self._keys_list_key)
        if stored:
            return json.loads(stored)
        return []

    def __iter__(self):
        return iter(self.keys())

    def __contains__(self, key):
        return key in self.keys()

    def _track_key(self, key):
        tracked_keys = self.keys()
        if key not in tracked_keys:
            tracked_keys.append(key)
            keyring.set_password(self._application_name, self._keys_list_key, json.dumps(tracked_keys))

    def _untrack_key(self, key):
        tracked_keys = self.keys()
        if key in tracked_keys:
            tracked_keys.remove(key)
            if tracked_keys:
                keyring.set_password(self._application_name, self._keys_list_key, json.dumps(tracked_keys))
            else:
                keyring.delete_password(self._application_name, self._keys_list_key)

    def _get_availability(self):
        backend = keyring.get_keyring()
        return not isinstance(backend, (fail.Keyring, null.Keyring))
