import platform
import subprocess
import os
import json
from typing import Dict, List, Optional


class SystemInfo:
    """Gather and cache system information for CVE validation."""

    def __init__(self):
        self._cache = {}
        self._gather_all()

    def _gather_all(self):
        """Gather all system information at initialization."""
        self._cache["os"] = self._get_os_info()
        self._cache["packages"] = self._get_installed_packages()
        self._cache["services"] = self._get_running_services()
        self._cache["kernel"] = self._get_kernel_info()
        self._cache["network"] = self._get_network_info()

    def _get_os_info(self) -> Dict[str, str]:
        """Get operating system information."""
        try:
            info = {
                "system": platform.system(),
                "node": platform.node(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "platform": platform.platform(),
                "python_version": platform.python_version(),
            }

            # Try to get Linux distribution info
            if platform.system() == "Linux":
                try:
                    import distro

                    info["distribution"] = distro.name()
                    info["distribution_version"] = distro.version()
                    info["distribution_id"] = distro.id()
                except:
                    # Fallback to checking files
                    if os.path.exists("/etc/os-release"):
                        with open("/etc/os-release", "r") as f:
                            for line in f:
                                if line.startswith("ID="):
                                    info["distribution_id"] = (
                                        line.split("=")[1].strip().strip('"')
                                    )
                                elif line.startswith("VERSION="):
                                    info["distribution_version"] = (
                                        line.split("=")[1].strip().strip('"')
                                    )
                                elif line.startswith("NAME="):
                                    info["distribution"] = (
                                        line.split("=")[1].strip().strip('"')
                                    )

            return info
        except Exception as e:
            return {"error": str(e)}

    def _get_installed_packages(self) -> Dict[str, Dict[str, str]]:
        """Get list of installed packages with versions."""
        packages = {}

        # Try different package managers
        if platform.system() == "Linux":
            # Try dpkg (Debian/Ubuntu)
            packages.update(self._get_dpkg_packages())
            # Try rpm (RedHat/CentOS/Rocky)
            packages.update(self._get_rpm_packages())
            # Try pip packages
            packages.update(self._get_pip_packages())

        return packages

    def _get_dpkg_packages(self) -> Dict[str, Dict[str, str]]:
        """Get packages from dpkg."""
        packages = {}
        try:
            result = subprocess.run(
                ["dpkg", "-l"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.startswith("ii"):
                        parts = line.split()
                        if len(parts) >= 3:
                            packages[parts[1]] = {
                                "version": parts[2],
                                "manager": "dpkg",
                            }
        except:
            pass
        return packages

    def _get_rpm_packages(self) -> Dict[str, Dict[str, str]]:
        """Get packages from rpm."""
        packages = {}
        try:
            result = subprocess.run(
                ["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}\\n"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if "\\t" in line:
                        name, version = line.split("\\t", 1)
                        packages[name] = {"version": version, "manager": "rpm"}
        except:
            pass
        return packages

    def _get_pip_packages(self) -> Dict[str, Dict[str, str]]:
        """Get Python packages."""
        packages = {}
        try:
            result = subprocess.run(
                ["pip", "list", "--format=json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                pip_packages = json.loads(result.stdout)
                for pkg in pip_packages:
                    packages[pkg["name"]] = {
                        "version": pkg["version"],
                        "manager": "pip",
                    }
        except:
            pass
        return packages

    def _get_running_services(self) -> List[Dict[str, str]]:
        """Get list of running services/processes."""
        services = []
        try:
            # Try systemctl for systemd systems
            result = subprocess.run(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--state=running",
                    "--no-pager",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if ".service" in line:
                        parts = line.split()
                        if len(parts) >= 1:
                            services.append(
                                {
                                    "name": parts[0].replace(".service", ""),
                                    "type": "systemd",
                                }
                            )

            # Also check listening ports
            result = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n")[1:]:  # Skip header
                    if "LISTEN" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            services.append(
                                {"address": parts[3], "type": "listening_port"}
                            )
        except:
            pass
        return services

    def _get_kernel_info(self) -> Dict[str, str]:
        """Get kernel information."""
        info = {}
        try:
            result = subprocess.run(
                ["uname", "-r"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                info["release"] = result.stdout.strip()

            result = subprocess.run(
                ["uname", "-v"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                info["version"] = result.stdout.strip()
        except:
            pass
        return info

    def _get_network_info(self) -> Dict[str, List[str]]:
        """Get network interface information."""
        info = {"interfaces": [], "listening_ports": []}
        try:
            # Get interfaces
            result = subprocess.run(
                ["ip", "addr"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                current_interface = None
                for line in result.stdout.split("\n"):
                    if ": " in line and not line.startswith(" "):
                        parts = line.split(": ", 2)
                        if len(parts) >= 2:
                            current_interface = parts[1].split("@")[0]
                            info["interfaces"].append(current_interface)

            # Get listening ports
            result = subprocess.run(
                ["ss", "-tln"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n")[1:]:  # Skip header
                    if "LISTEN" in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            info["listening_ports"].append(parts[3])
        except:
            pass
        return info

    def get_all(self) -> Dict[str, any]:
        """Get all cached system information."""
        return self._cache

    def get_package_version(self, package_name: str) -> Optional[str]:
        """Get version of a specific package."""
        packages = self._cache.get("packages", {})
        if package_name in packages:
            return packages[package_name]["version"]

        # Try common variations
        variations = [
            package_name.lower(),
            package_name.upper(),
            package_name.replace("-", "_"),
            package_name.replace("_", "-"),
        ]

        for variant in variations:
            if variant in packages:
                return packages[variant]["version"]

        return None

    def is_service_running(self, service_name: str) -> bool:
        """Check if a service is running."""
        services = self._cache.get("services", [])
        for service in services:
            if service.get("name", "").lower() == service_name.lower():
                return True
        return False

    def is_port_listening(self, port: int) -> bool:
        """Check if a port is listening."""
        ports = self._cache.get("network", {}).get("listening_ports", [])
        port_str = str(port)
        for addr in ports:
            if f":{port_str}" in addr:
                return True
        return False


# Singleton instance
_system_info_instance = None


def get_system_info() -> SystemInfo:
    """Get or create the singleton SystemInfo instance."""
    global _system_info_instance
    if _system_info_instance is None:
        _system_info_instance = SystemInfo()
    return _system_info_instance
