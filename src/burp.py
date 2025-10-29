import subprocess
import psutil
import json
import platform
import os
from pathlib import Path
from .utils import logger

from mitmproxy.certs import CertStore


class Burp:
    """Verify and configure Burp Suite for proxy interception.

    Creates mitmproxy certificate, installs it in Burp's keystore, enables AI feature,
    and configures upstream proxy. Requires Burp to be closed if changes are needed.
    """

    def __init__(self, config):
        self.burpsuite_dir = Path(config["burpsuite_dir"]).expanduser()
        self.burpsuite_config_dir = Path(config["burpsuite_config_dir"]).expanduser()
        self.mitmproxy_config_dir = Path(config["mitmproxy_config_dir"]).expanduser()

        system = platform.system()

        if system == "Darwin":
            jre_base = self.burpsuite_dir / "Contents" / "Resources" / "jre.bundle" / "Contents" / "Home"
            keytool_name = "keytool"
        elif system == "Windows":
            jre_base = self.burpsuite_dir / "jre"
            keytool_name = "keytool.exe"
        else:  # Linux and others
            jre_base = self.burpsuite_dir / "jre"
            keytool_name = "keytool"

        self.cert_path = self.mitmproxy_config_dir / "mitmproxy-ca-cert.cer"

        self.keytool_path = jre_base / "bin" / keytool_name
        self.keystore_path = jre_base / "lib" / "security" / "cacerts"
        self.burp_config_path = self.burpsuite_config_dir / "UserConfigPro.json"

        self.expected_proxy_server = {
            "destination_host": "ai.portswigger.net",
            "enabled": True,
            "proxy_host": "localhost",
            "proxy_port": config["port"],
        }

    def setup(self):
        logger.info("Checking Burp Suite setup ...")

        if not self._validate_directories():
            return False

        if not self._create_certificates():
            return False

        return self._check_and_update_configuration()

    def _validate_directories(self):
        if not self.burpsuite_dir.exists():
            logger.error("Burp Suite installation not found under %s", self.burpsuite_dir)
            logger.error("If necessary, you can specify a different path using the --burpsuite-dir option")
            return False

        if not os.access(self.burpsuite_dir, os.W_OK):
            logger.error("Burp Suite installation directory is not writable: %s", self.burpsuite_dir)
            return False

        if not self.burpsuite_config_dir.exists():
            logger.error("Burp Suite config directory not found under %s", self.burpsuite_config_dir)
            logger.error("If necessary, you can specify a different path using the --burpsuite-config-dir option")
            return False

        if not os.access(self.burpsuite_config_dir, os.W_OK):
            logger.error("Burp Suite config directory is not writable: %s", self.burpsuite_config_dir)
            return False

        return True

    def _create_certificates(self):
        self.cert_path.parent.mkdir(exist_ok=True)

        if self.cert_path.exists():
            return True

        logger.info("Creating new mitmproxy certificate...")
        CertStore.from_store(str(self.cert_path.parent), "mitmproxy", 2048)

        if not self.cert_path.exists():
            logger.error("Certificate file was not created at %s", self.cert_path)
            logger.error("Consider recreating %s", self.cert_path.parent)
            return False

        logger.info("New certificate created")
        return True

    def _check_and_update_configuration(self):
        burp_running = self._is_burp_running()
        cert_matches = self._cert_matches_burp()
        ai_enabled, proxy_correct = self._check_burp_config()
        config_correct = ai_enabled and proxy_correct

        cert_status = f"{'[green]Yes[/green]' if cert_matches else '[red]No[/red]'}"
        logger.info(f"  - Custom certificate in keystore: {cert_status}")

        ai_status = f"{'[green]Yes[/green]' if ai_enabled else '[red]No[/red]'}"
        logger.info(f"  - AI feature flag enabled: {ai_status}")

        proxy_status = f"{'[green]Yes[/green]' if proxy_correct else '[red]No[/red]'}"
        logger.info(f"  - Upstream proxy properly configured: {proxy_status}")

        needs_cert_update = not cert_matches
        needs_config_update = not config_correct

        if burp_running and (needs_cert_update or needs_config_update):
            logger.info("  - Burp Suite running: [red]Yes[/red]")
        elif burp_running:
            logger.info("  - Burp Suite running: Yes")
        else:
            logger.info("  - Burp Suite running: No")

        if burp_running and (needs_cert_update or needs_config_update):
            logger.error("Please close Burp Suite first and then try it again. Exiting...")
            return False

        if needs_cert_update and not self._add_cert_to_burp():
            return False

        return not (needs_config_update and not self._update_burp_config(ai_enabled, proxy_correct))

    def _is_burp_running(self):
        """Check if Burp Suite is running, working on all relevant platforms."""
        system = platform.system()
        for process in psutil.process_iter(["name", "cmdline", "exe"]):
            name = process.info.get("name")
            cmdline = process.info.get("cmdline")
            exe = process.info.get("exe", "")

            if system == "Darwin" and name == "JavaApplicationStub" and "Burp Suite Professional.app" in exe:
                return True
            if system == "Windows" and name == "BurpSuitePro.exe":
                return True
            if cmdline and any("install4j.burp.StartBurp" in arg for arg in cmdline):
                return True

        return False

    def _cert_matches_burp(self):
        """Check if mitmproxy cert matches the one in Burp's keystore."""
        if not self.keytool_path.exists() or not self.cert_path.exists():
            return False

        burp_result = self._run_keytool(
            [
                "-exportcert",
                "-alias",
                "mitmproxy",
                "-keystore",
                str(self.keystore_path),
                "-rfc",
            ]
        )

        if burp_result.returncode != 0:
            return False

        with self.cert_path.open() as f:
            mitmproxy_cert = f.read()

        return burp_result.stdout.strip() == mitmproxy_cert.strip()

    def _check_burp_config(self):
        """Check if Burp config has correct upstream proxy and AI settings."""
        burp_config = self._load_burp_config()
        if not burp_config:
            if not self.burp_config_path.exists():
                logger.warning("Burp config file not found")
            return False, False

        user_options = burp_config.get("user_options", {})

        ai_enabled = user_options.get("ai", {}).get("enabled", False)

        servers = user_options.get("connections", {}).get("upstream_proxy", {}).get("servers", [])

        proxy_correct = False
        if servers:
            first_server = servers[0]
            proxy_correct = all(first_server.get(key) == value for key, value in self.expected_proxy_server.items())

        return ai_enabled, proxy_correct

    def _add_cert_to_burp(self):
        """Delete the mitmproxy certificate and add it to the Burp Suite keystore."""
        if not self.keytool_path.exists():
            logger.error("keytool not found at %s", self.keytool_path)
            logger.error("Please ensure Burp Suite Pro is properly installed with Java runtime")
            return False

        logger.info("Refreshing certificate in Burp Suite...")

        self._run_keytool(
            [
                "-delete",
                "-alias",
                "mitmproxy",
                "-keystore",
                str(self.keystore_path),
            ]
        )

        result = self._run_keytool(
            [
                "-importcert",
                "-trustcacerts",
                "-alias",
                "mitmproxy",
                "-file",
                str(self.cert_path),
                "-keystore",
                str(self.keystore_path),
                "-noprompt",
            ]
        )

        if result.returncode == 0:
            logger.info("Certificate updated in Burp Suite keystore")
            return True

        logger.error("Failed to add certificate: %s", result.stderr.strip())
        return False

    def _update_burp_config(self, ai_enabled=False, proxy_correct=False):
        """Update Burp config with correct upstream proxy and AI setting."""
        burp_config = self._load_burp_config()
        if not burp_config:
            return False

        changes = []
        user_options = burp_config.setdefault("user_options", {})

        if not ai_enabled:
            ai_config = user_options.setdefault("ai", {})
            ai_config["enabled"] = True
            changes.append("Enabled AI feature")

        if not proxy_correct:
            user_options.setdefault("connections", {}).setdefault("upstream_proxy", {}).setdefault("servers", [])
            servers = burp_config["user_options"]["connections"]["upstream_proxy"]["servers"]

            servers_before = len(servers)
            dest_host = self.expected_proxy_server["destination_host"]
            servers = [s for s in servers if s.get("destination_host") != dest_host]
            proxy_exists = len(servers) < servers_before

            servers.insert(0, self.expected_proxy_server)

            burp_config["user_options"]["connections"]["upstream_proxy"]["servers"] = servers

            port = self.expected_proxy_server["proxy_port"]
            if proxy_exists:
                changes.append(f"Updated proxy for {dest_host} -> localhost:{port}")
            else:
                changes.append(f"Added proxy for {dest_host} -> localhost:{port}")

        with self.burp_config_path.open("w") as f:
            json.dump(burp_config, f, indent=2)

        if changes:
            logger.info("Updated Burp config:")
            for change in changes:
                logger.info("  - %s", change)
        return True

    def _load_burp_config(self):
        if not self.burp_config_path.exists():
            return None
        with self.burp_config_path.open() as f:
            return json.load(f)

    def _run_keytool(self, args):
        return subprocess.run(
            [str(self.keytool_path)] + args,
            capture_output=True,
            text=True,
            check=False,
        )
