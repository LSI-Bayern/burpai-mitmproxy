import json
import platform
import os
from pathlib import Path
from .utils import logger

import psutil
from mitmproxy.certs import CertStore


class Burp:
    """Verify and configure Burp Suite for proxy interception.

    Creates mitmproxy certificate, adds it to Burp's config, enables AI feature,
    and configures upstream proxy. Requires Burp to be closed if changes are needed.
    """

    def __init__(self, config):
        self.burpsuite_config_dir = Path(config["burpsuite_config_dir"]).expanduser()
        self.mitmproxy_config_dir = Path(config["mitmproxy_config_dir"]).expanduser()

        self.cert_path = self.mitmproxy_config_dir / "mitmproxy-ca-cert.cer"
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

    def _get_cert_der_base64(self):
        """Read PEM certificate and return as single-line base64 DER string."""
        with self.cert_path.open() as f:
            pem_content = f.read()

        lines = pem_content.strip().splitlines()
        base64_lines = [line for line in lines if not line.startswith("-----")]
        return "".join(base64_lines)

    def _check_and_update_configuration(self):
        burp_running = self._is_burp_running()
        cert_installed, ai_enabled, proxy_correct = self._check_burp_config()

        cert_status = f"{'[green]Yes[/green]' if cert_installed else '[red]No[/red]'}"
        logger.info(f"  - Custom certificate in config: {cert_status}")

        ai_status = f"{'[green]Yes[/green]' if ai_enabled else '[red]No[/red]'}"
        logger.info(f"  - AI feature flag enabled: {ai_status}")

        proxy_status = f"{'[green]Yes[/green]' if proxy_correct else '[red]No[/red]'}"
        logger.info(f"  - Upstream proxy properly configured: {proxy_status}")

        needs_update = not (cert_installed and ai_enabled and proxy_correct)

        if burp_running and needs_update:
            logger.info("  - Burp Suite running: [red]Yes[/red]")
        elif burp_running:
            logger.info("  - Burp Suite running: Yes")
        else:
            logger.info("  - Burp Suite running: No")

        if burp_running and needs_update:
            logger.error("Please close Burp Suite first and then try it again. Exiting...")
            return False

        if needs_update:
            return self._update_burp_config(cert_installed, ai_enabled, proxy_correct)

        return True

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

    def _check_burp_config(self):
        """Check if Burp config has correct certificate, upstream proxy and AI settings."""
        burp_config = self._load_burp_config()
        if not burp_config:
            if not self.burp_config_path.exists():
                logger.warning("Burp config file not found")
            return False, False, False

        user_options = burp_config.get("user_options", {})

        cert_der_b64 = self._get_cert_der_base64()
        custom_certs = user_options.get("ssl", {}).get("custom_ca_certificates", [])
        cert_installed = cert_der_b64 in custom_certs

        ai_enabled = user_options.get("ai", {}).get("enabled", False)

        servers = user_options.get("connections", {}).get("upstream_proxy", {}).get("servers", [])
        proxy_correct = False
        if servers:
            first_server = servers[0]
            proxy_correct = all(first_server.get(key) == value for key, value in self.expected_proxy_server.items())

        return cert_installed, ai_enabled, proxy_correct

    def _update_burp_config(self, cert_installed=False, ai_enabled=False, proxy_correct=False):
        """Update Burp config with certificate, upstream proxy and AI setting."""
        burp_config = self._load_burp_config()
        if burp_config is None:
            burp_config = {}

        changes = []
        user_options = burp_config.setdefault("user_options", {})

        if not cert_installed:
            ssl_config = user_options.setdefault("ssl", {})
            custom_certs = ssl_config.setdefault("custom_ca_certificates", [])
            cert_der_b64 = self._get_cert_der_base64()
            if cert_der_b64 not in custom_certs:
                custom_certs.append(cert_der_b64)
            changes.append("Added mitmproxy CA certificate")

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
