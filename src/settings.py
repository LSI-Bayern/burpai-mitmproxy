import json
import platform
import shutil
import subprocess
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from collections.abc import Callable

from .utils import ask, ask_yn, logger
from .vault import Vault


@dataclass
class SettingField:
    type: type
    default: Any
    prompt: str | None = None
    example: str | None = None
    info: str | None = None
    is_secret: bool = False
    validator: Callable[[Any], bool] | None = None


@dataclass
class PlatformDefaults:
    burpsuite_dir: str
    burpsuite_config_dir: str
    mitmproxy_config_dir: str
    burpai_config_path: str


class Settings:
    """Manages application settings with support for secrets in system keyring."""

    def __init__(self):
        self._vault = Vault()

        self.provider_aliases = {
            "anthropic": "https://api.anthropic.com/v1",
            "openai": "https://api.openai.com/v1",
            "google": "https://generativelanguage.googleapis.com/v1beta/openai/",
        }

        platform_defaults = self._get_platform_defaults()

        def validate_url(url):
            if not url:
                return True
            if url in self.provider_aliases:
                return True
            if not url.startswith(("http://", "https://")):
                logger.error("URL must include http:// or https:// protocol")
                return False
            return True

        self.schema = {
            "api_key": SettingField(
                type=str,
                default=None,
                prompt="Enter your API key",
                example='usually "sk-...", leave empty if not required',
                is_secret=True,
            ),
            "no_auth_urls": SettingField(
                type=list,
                default=["http://localhost:11434/v1"],
            ),
            "llm_url": SettingField(
                type=str,
                default="http://localhost:11434/v1",
                prompt="Enter the LLM base URL or an alias",
                info=(
                    f"The following provider aliases are supported: "
                    f"{', '.join(f'[cyan]{alias}[/cyan]' for alias in self.provider_aliases)}"
                ),
                validator=validate_url,
            ),
            "model": SettingField(
                type=str,
                default="qwen3-coder:30b-32k",
                prompt="Enter the model name",
            ),
            "token_limit": SettingField(
                type=int,
                default=32000,
                prompt="Enter the token limit",
            ),
            "port": SettingField(
                type=int,
                default=8765,
            ),
            "burpsuite_dir": SettingField(
                type=Path,
                default=platform_defaults.burpsuite_dir,
            ),
            "burpsuite_config_dir": SettingField(
                type=Path,
                default=platform_defaults.burpsuite_config_dir,
            ),
            "mitmproxy_config_dir": SettingField(
                type=Path,
                default=platform_defaults.mitmproxy_config_dir,
            ),
            "proxy": SettingField(
                type=str,
                default=None,
            ),
            "proxy_username": SettingField(
                type=str,
                default=None,
                is_secret=True,
            ),
            "proxy_password": SettingField(
                type=str,
                default=None,
                is_secret=True,
            ),
        }

        self.config_path = Path(platform_defaults.burpai_config_path).expanduser()
        self._user_config = {}

    def load_config(self):
        """Load settings from disk, creating empty file if it doesn't exist."""
        if not self.config_path.exists():
            self.config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.config_path.touch(mode=0o600)
            self.config_path.write_text(json.dumps({}))
            logger.info("Created settings file under %s", self.config_path)
            self._user_config = {}
            return True

        with self.config_path.open() as file:
            try:
                self._user_config = json.load(file)
                return True
            except json.JSONDecodeError as e:
                logger.error("Settings file under %s is not a valid JSON:\n%s", self.config_path, e)
                logger.info("Use [cyan]-s[/cyan] to edit the settings file or [cyan]--reset[/cyan] to start fresh")
                return False

    def resolve(self, overrides):
        """Resolve all configured settings, applying optional overrides."""
        if overrides is None:
            overrides = {}
        result = {}

        # Warn about unrecognized keys
        for key in self._user_config:
            if key not in self.schema:
                logger.warning("Unrecognized key in settings: [cyan]%s[/cyan]", key)

        # Retrieve all settings
        url, success = self._get("llm_url", override_value=overrides.get("llm_url"))
        if not success:
            return None
        result["llm_url"] = url

        for key in self.schema:
            if key == "llm_url":
                continue
            value, success = self._get(key, override_value=overrides.get(key), url=url)

            if not success:
                # Validation/conversion failed
                return None
            result[key] = value

        # Display all settings
        logger.info("Settings:")
        logger.info("  - [cyan]%s[/cyan]: [cyan]%s[/cyan]", "llm_url", url)

        for key in self.schema:
            if key == "llm_url":
                continue
            if self.schema[key].is_secret:
                if result[key]:
                    keyring_key = self._get_keyring_key(key, url)
                    logger.info("  - [cyan]%s[/cyan] -> retrieved from keyring", keyring_key)
                else:
                    logger.info("  - [cyan]%s[/cyan] -> None", key)
            else:
                logger.info("  - [cyan]%s[/cyan]: [cyan]%s[/cyan]", key, result[key])

        return result

    def reset(self):
        """Delete entire settings directory and all stored secrets after confirmation."""
        prompt = "Do you want to delete the settings directory and all secrets associated with burpai? (y/n)"
        if not ask_yn(prompt):
            return

        if self._vault.is_available:
            self.delete_secrets(interactive=False)

        config_dir = self.config_path.parent
        if config_dir.exists():
            shutil.rmtree(config_dir)
            logger.info("Deleted settings directory at %s", config_dir)
        else:
            logger.info("Settings directory at %s does not exist", config_dir)

        self._user_config = {}

    def delete_secrets(self, interactive=True):
        """Remove all secrets from system keyring, optionally prompting for confirmation."""
        prompt = "Do you want to delete all secrets associated with burpai? (y/n)"
        if interactive and not ask_yn(prompt):
            return

        for key in self._vault:
            self._vault.delete(key)

    def spawn_editor(self):
        """Open settings file in user's preferred editor ($VISUAL, $EDITOR, or platform default)."""
        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")

        if not editor:
            system = platform.system()
            if system == "Windows":
                editor = "notepad.exe"
            else:  # Linux, Darwin and others
                for candidate in ["nano", "vim", "vi"]:
                    if shutil.which(candidate):
                        editor = candidate
                        break
                else:
                    logger.error("No editor found. Set $EDITOR environment variable.")
                    return False

        logger.info("Opening settings file: %s", self.config_path)
        try:
            subprocess.run([editor, str(self.config_path)], check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Failed to open editor: %s", e)
            return False

    def _build_prompt(self, key):
        param = self.schema[key]
        base_prompt = param.prompt
        if not base_prompt:
            return ""

        default = param.default
        example = param.example

        full_prompt = f"{base_prompt}:"

        # Show default
        if default is not None:
            full_prompt = f'{base_prompt} (ENTER for "{default}"):'

        # Show example
        elif example:
            full_prompt = f"{base_prompt} ({example}):"

        return full_prompt

    def _get(self, key, override_value=None, url=None):
        """Retrieve setting value from storage or prompt user if needed.

        Secrets are fetched from system keyring; non-secrets from JSON file.
        Prompts interactively for missing values when configured with a prompt.

        Returns:
            tuple: (value, success)

        """
        if key not in self.schema:
            return self._user_config.get(key), True

        field = self.schema[key]

        if field.is_secret:
            value, success = self._get_secret_value(key, url, override_value)
        else:
            value, success = self._get_non_secret_value(key, override_value)

        # Validate the final value (from any source: override, json, or prompt)
        if not success or (value is not None and field.validator and not field.validator(value)):
            return None, False

        # Convert value to expected type
        if value is None:
            return value, True

        # Expand provider aliases for llm_url
        if key == "llm_url" and isinstance(value, str) and value in self.provider_aliases:
            value = self.provider_aliases[value]

        expected_type = field.type

        try:
            value = str(Path(value).expanduser()) if expected_type is Path else expected_type(value)
            return value, True
        except (ValueError, TypeError):
            type_name = "path" if expected_type is Path else expected_type.__name__
            logger.error(
                "Invalid %s value [yellow]%s[/yellow] for [cyan]%s[/cyan]",
                type_name,
                value,
                key,
            )
            logger.info("Use [cyan]-s[/cyan] to edit the settings file")
            return None, False

    def _get_secret_value(self, key, url, override_value):
        """Get secret value from override, vault, or prompt.

        Returns:
            tuple: (value, success)

        """
        if override_value is not None:
            return override_value, True

        # Check if URL doesn't require authentication
        if key == "api_key" and url:
            no_auth_urls, success = self._get("no_auth_urls")
            if not success:
                return None, False
            if url in no_auth_urls:
                return None, True

        # Try to get from vault if tracked
        keyring_key = self._get_keyring_key(key, url)
        value = self._vault.get(keyring_key) if keyring_key in self._vault else None

        # Prompt if not found
        if value is None and self.schema[key].prompt is not None:
            return self._prompt_for_secret(key, url)

        return value, True

    def _get_platform_defaults(self):
        """Get platform-specific default paths."""
        defaults = {
            "Darwin": PlatformDefaults(
                burpsuite_dir="/Applications/Burp Suite Professional.app",
                burpsuite_config_dir="~/.BurpSuite",
                mitmproxy_config_dir="~/Library/Application Support/mitmproxy",
                burpai_config_path="~/Library/Application Support/burpai/settings.json",
            ),
            "Windows": PlatformDefaults(
                burpsuite_dir="~/AppData/Local/Programs/BurpSuitePro",
                burpsuite_config_dir="~/AppData/Roaming/BurpSuite",
                mitmproxy_config_dir="~/.mitmproxy",
                burpai_config_path="~/AppData/Roaming/burpai/settings.json",
            ),
            "Linux": PlatformDefaults(
                burpsuite_dir="~/BurpSuitePro",
                burpsuite_config_dir="~/.BurpSuite",
                mitmproxy_config_dir="~/.mitmproxy",
                burpai_config_path="~/.config/burpai/settings.json",
            ),
        }

        return defaults.get(platform.system(), defaults["Linux"])

    def _prompt_for_secret(self, key, url):
        """Prompt user for secret value.

        Returns:
            tuple: (value, success)

        """
        if url:
            logger.info("Requesting credentials for [cyan]%s[/cyan]", url)

        full_prompt = self._build_prompt(key)
        validator = self.schema[key].validator
        value = ask(full_prompt, is_secret=True, validator=validator)

        if value:
            self._update(key, value, url=url)
            return value, True

        # Handle empty value for api_key with URL
        if key == "api_key" and url:
            no_auth_urls, success = self._get("no_auth_urls")
            if not success:
                return None, False
            if url not in no_auth_urls:
                no_auth_urls.append(url)
                self._update("no_auth_urls", no_auth_urls)
            return None, True

        # Return error if required field was left empty
        if self.schema[key].default is None:
            logger.error("[cyan]%s[/cyan] was left empty", key)
            return None, False

        return value, True

    def _get_non_secret_value(self, key, override_value):
        """Get non-secret value from config or prompt.

        Returns:
            tuple: (value, success)

        """
        if key in self._user_config and override_value is None:
            return self._user_config[key], True

        if override_value is not None:
            return override_value, True

        # Prompt for value if not in config
        field = self.schema[key]
        value = None
        if field.prompt is not None:
            if field.info is not None:
                logger.info(field.info)
            full_prompt = self._build_prompt(key)
            validator = field.validator
            value = ask(full_prompt, is_secret=False, validator=validator)

        if not value:
            value = field.default

        # Return error if prompted but empty with no default
        if value is None and field.prompt is not None:
            logger.error("[cyan]%s[/cyan] was left empty", key)
            return None, False

        if value is not None:
            self._update(key, value)

        return value, True

    def _update(self, key, value, url=None):
        """Store setting value, routing secrets to keyring and non-secrets to JSON file."""
        # Secret values -> keyring (vault handles tracking automatically)
        if key in self.schema and self.schema[key].is_secret:
            keyring_key = self._get_keyring_key(key, url)
            self._vault.set(keyring_key, value)
            return

        # Non-secrets -> JSON config
        self._user_config[key] = value
        self._save_config()

    def _delete(self, key):
        """Remove non-secret setting from JSON file."""
        if key in self._user_config:
            del self._user_config[key]
            self._save_config()
            logger.info("Deleted [cyan]%s[/cyan] from settings", key)

    def _save_config(self):
        with self.config_path.open("w") as file:
            json.dump(self._user_config, file, indent=4)

    def _get_keyring_key(self, key, url=None):
        if url:
            return f"{key}@{url}"
        return key
